#!/usr/bin/perl

package Net::Bluetooth::Sunny;

use Net::Bluetooth;
use strict;
use Data::Dumper;

my $HAS_COLOR;
my $NAMES;
BEGIN {    

    eval {
        require "Term/ANSIColor.pm";
        Term::ANSIColor->import();        
    };
    $HAS_COLOR = 1 unless $@;
    die $@ if $@;
   
}

my $ADDRESS_UNKNOWN = "FF:FF:FF:FF:FF:FF";
my $ANY_SUSY_ID = 0xFFFF;
my $ANY_SERIAL_ID = 0xFFFFFFFF;
my $APP_SUSY_ID = 125;
my $L2_SIGNATURE = 0x656003FF;
my @FCSTAB;
my $INVERTER_COMMANDS;
my $INVERTER_EXTRACTORS;


init_NAMES();

sub new { 
    my $class = shift;
    my $self = ref($_[0]) eq "HASH" ? $_[0] : {  @_ };
    bless $self,(ref($class) || $class);
    $self->{appSerial} ||= 900000000 + int(rand(100000000));

    return $self;
}

sub connect {
    my $self = shift;
    my $addr = shift || $self->{"address"} || die "No target address given";

    my $bt = Net::Bluetooth->newsocket("RFCOMM");
    die "socket error $!\n" unless(defined($bt)); 
    if ($bt->connect($addr, "1") != 0) {
        die "Cannot connect to $addr: $!\n";
    }
    $self->{bt} = $bt;
}

sub disconnect {
    my $self = shift;
    $self->{bt} && $self->{bt}->close();
    delete $self->{bt};
}


sub init { 
    my $self = shift;

    # Initial requests
    # Get netid
    $self->init_netid();

    # Find address
    $self->init_addresses();

    # Initialise inverter data
    $self->init_inverters();
    
    # Logoff 
    $self->logoff();
}

sub bt_strength {
    my $self = shift;
    $self->write_l1(0x03,[ 0x05, 0x00]);
    my $resp = $self->read_l1(0x04);
    return _resp_byte($resp,4) * 100 / 255;
}

sub logoff {
    my $self = shift;

    my $cmd = {
               command => 0x01,
               destAddress => $ADDRESS_UNKNOWN,
               longwords => 0x08,
               ctrl => 0xA0,
               ctrl2 => 0x0300,
               susyId => $ANY_SUSY_ID,
               serialId => $ANY_SERIAL_ID,
               extra => pack("V*",0xFFFD010E, 0xFFFFFFFF)
              };
    $self->write_l2($cmd);        
    $self->{loggedIn} = 0;
}

sub login {
    my $self = shift;
    my $password = shift || die "No password given";
    my $user = shift || "user";
    
    my ($user_group,$enc) = lc($user) eq "installer" ? (0x0A,0xBB) : (0x07,0x88);

    my $pw_enc = $self->_encode_password($password,$enc);

    my $now = time;
    my $cmd = {
               command => 0x01,
               destAddress => $ADDRESS_UNKNOWN,
               longwords => 0x0E,
               ctrl => 0xA0,
               ctrl2 => 0x0100,
               susyId => $ANY_SUSY_ID,
               serialId => $ANY_SERIAL_ID,
               extra => pack("V*",0xFFFD040C, $user_group, 0x00000384, $now, 0) . $pw_enc
              };
    $self->write_l2($cmd);
    my $resp = $self->read_l2();
    
    my $pkt_id_rcv = _resp_short($resp,27) & 0x7FFF;
    my $time_rcv = _resp_long($resp,41);
    my $inverter = $self->_inverter_from_pkt($resp);
    my $success = _resp_byte($resp,24) == 0;

    $self->dbg("Packet-Id: ",$pkt_id_rcv," (own : ",$self->{_packetId},")");
    $self->dbg("Time:      ",$time_rcv," (given: ",$now,")");

    # TODO: Might retry for different converters. Only tested in a single
    # converter environment.

    die "Invalid password" unless $success;
    $self->{loggedIn} = 1;
}

sub info {
    my $self = shift;
    die "Not logged in" unless $self->{loggedIn};
    
    my $info = $self->_squeeze_query_result($self->_query("Software","TypeLabel","DeviceStatus","InverterTemperature"));

    # Add info obtained during initialization
    for my $addr (keys %$info) {
        my $inverter = $self->{inverters}->{$addr};
        map { $info->{$addr}->{$_} = $inverter->{$_} } keys %$inverter;
    }
    return $info;
}

sub energy {
    my $self = shift;
    die "Not logged in" unless $self->{loggedIn};
    
    return $self->_squeeze_query_result($self->_query("EnergyProduction"));
}

sub operation_time {
    my $self = shift;
    die "Not logged in" unless $self->{loggedIn};
    
    return $self->_squeeze_query_result($self->_query("OperationTime"));
}

sub dc {
    my $self = shift;
    die "Not logged in" unless $self->{loggedIn};
    
    return $self->_squeeze_query_result($self->_query("SpotDCPower","SpotDCVoltage"));
}

sub ac {
    my $self = shift;
    die "Not logged in" unless $self->{loggedIn};
    
    return $self->_squeeze_query_result($self->_query("SpotACPower","SpotACVoltage","SpotACTotalPower"));
}

sub frequency {
    my $self = shift;
    die "Not logged in" unless $self->{loggedIn};

    return $self->_squeeze_query_result($self->_query("SpotGridFrequency"));
}

# =========================================================================================== 

sub _squeeze_query_result {
    my $self = shift;
    my $ret = {};
    for my $resps (@_) {
        #print Dumper($resps);
        for my $inverter (keys %$resps) {
            my $cmd_resp = $resps->{$inverter};
            for my $values (values %$cmd_resp) {
                for my $entry (@$values) {
                    my $res = $entry->{res};
                    map { $ret->{$inverter}->{$_} = $res->{$_} } keys %$res;
                }
            }
        }
    }
    return $ret;
}

sub _query {
    my $self = shift;
    die "No initialized yet or no inverter found" unless %{$self->{inverters}};
    my @ret = ();
    for my $key (@_) {
        my $sub_cmd = $INVERTER_COMMANDS->{$key} || die "No subcommands for $key given";
        my $cmd = {
                   command => 0x01,
                   destAddress => $ADDRESS_UNKNOWN,
                   longwords => 0x09,
                   ctrl => 0xA0,
                   ctrl2 => 0,
                   susyId => $ANY_SUSY_ID,
                   serialId => $ANY_SERIAL_ID,
                   extra => pack("V*",$sub_cmd->{command},$sub_cmd->{first},$sub_cmd->{last})
                  };
        $self->write_l2($cmd);
        my $inverters = $self->{inverters};
        my $ret = {};
        for my $inv_address (keys %$inverters) {
            # TODO: Multiple reads for each inverter
            my $resp = $self->read_l2();
            my $i = 41;
            my $end = length($resp->{data}) - 3;
            my $map = {};
            while ($i < $end) {
                my $code = _resp_long($resp,$i);
                my $lri = ($code & 0x00FFFF00) >> 8;
                my $cls = $code & 0x000000FF;
                my $dt  = ($code & 0xFF000000) >> 24;
                my $date = _resp_long($resp,$i+4);
                
                my $extractor = $INVERTER_EXTRACTORS->{$lri} || die sprintf "Cannot find extractor for %04x",$lri;
                my $sub = $extractor->{sub};
                my $opts = { cls => $cls, data_type => $dt, date => $date };
                push @{$map->{sprintf("0x%04x",$lri)}}, { res => &{$sub}($i,$resp,$opts), %$opts };
                $i += $extractor->{offset};
            }
            $ret->{$inv_address} = $map;
        }
        $self->dbg("Query '$key' = " ,Dumper($ret)) if $self->{debug};
        push @ret,$ret;
    }
    return @ret;
}

# ===============================================================
# Commands send
$INVERTER_COMMANDS = 
    {
     "Software" => {
                    command => 0x58000200,
                    first => 0x00823400,
                    last => 0x008234FF
                   },
     "TypeLabel" => {
                     command => 0x58000200,
                     first => 0x00821E00,
                     last => 0x008220FF
                    },
     "DeviceStatus" => {
                        command => 0x51800200,
                        first => 0x00214800,
                        last => 0x002148FF
                       },
     "InverterTemperature" => {
                        command => 0x52000200,
                        first => 0x00237700,
                        last => 0x002377FF
                       },
     # TODO: GridRelayStatus, MaxACPower, MaxACPower2
     "EnergyProduction" => {
                            command => 0x54000200,
                            first => 0x00260100,
                            last => 0x002622FF,
                           },
     "OperationTime" => {
                         command => 0x54000200,
                         first => 0x00462E00,
                         last => 0x00462FFF
                        },
     "SpotDCPower" => {
                       command => 0x53800200,
                       first => 0x00251E00,
                       last => 0x00251EFF
                      },
     "SpotDCVoltage" => {
                         command => 0x53800200,
                         first => 0x00451F00,
                         last => 0x004521FF
                        },
     "SpotACPower" => {
                       command => 0x51000200,
                       first => 0x00464000,
                       last => 0x004642FF
                      },
     "SpotACVoltage" => {
                         command => 0x51000200,
                         first => 0x00464800,
                         last => 0x004652FF
                        },
     "SpotACTotalPower" => {
                            command => 0x51000200,
                            first => 0x00263F00,
                            last => 0x00263FFF
                           },
     "SpotGridFrequency" => {
                             command => 0x51000200,
                             first => 0x00465700,
                             last => 0x004657FF
                            }
    };

# ==============================================================
# Extractors for response data 

$INVERTER_EXTRACTORS = 
    {
     # Software
     0x8234 => { sub => \&_x_software_version, offset => 40 },
     # TypeLabel
     0x821E => { sub => \&_x_inverter_name, offset => 40 },
     0x821F => { sub => _x_info("class"), offset => 40 },
     0x8220 => { sub => _x_info("type"), offset => 40},
     # DeviceStatus
     0x2148 => { sub => _x_info("status"), offset => 40},
     # InverterTemperature
     0x2377 => { sub => _x_value("temperature",100), offset => 28},
     # EnergyProduction
     0x2601 => { sub => _x_value_64("energy_total",1000), offset => 16},
     0x2622 => { sub => _x_value_64("energy_today",1000), offset => 16},
     # OperationTime
     0x462E => { sub => _x_value_64("operation_time",3600), offset => 16},
     0x462F => { sub => _x_value_64("feedin_time",3600), offset => 16},
     # SpotDCPower
     0x251E => { sub => _x_value_cls("dc_power"),offset => 28},
     # SpotDCVoltage
     0x451F => { sub => _x_value_cls("dc_voltage",100),offset => 28},     
     0x4521 => { sub => _x_value_cls("dc_current",1000),offset => 28},
     # SpotACPower
     0x4640 => { sub => _x_value("ac_power_1"),offset => 28},
     0x4641 => { sub => _x_value("ac_power_2"),offset => 28},
     0x4642 => { sub => _x_value("ac_power_3"),offset => 28},
     # SpotACVoltage
     0x4648 => { sub => _x_value("ac_voltage_1",100),offset => 28},
     0x4649 => { sub => _x_value("ac_voltage_2",100),offset => 28},
     0x464A => { sub => _x_value("ac_voltage_3",100),offset => 28},
     0x4650 => { sub => _x_value("ac_current_1",100),offset => 28},
     0x4651 => { sub => _x_value("ac_current_2",100),offset => 28},
     0x4652 => { sub => _x_value("ac_current_3",100),offset => 28},  
     # SpotACPowerTotal
     0x263F => { sub => _x_value("ac_power"),offset => 28},
     # SpotGridFrequency
     0x4657 => { sub => _x_value("freq"),offset => 28},
    };


sub _x_software_version {
    my ($o,$resp) = @_;
    my ($type,$build,$minor,$major) = _resp_byte($resp,$o + 24,4);
    my $release_type = $type > 5 ? $type : substr("NEABRS",$type,1);
    my $sw_version = sprintf("%d%d.%d%d.%02d.%s",$major >> 4,$major & 0x0F,$minor >> 4,$minor & 0x0F,$build,$release_type);
    return {
            "release_type" => $release_type,
            "sw_version" => $sw_version
           };
}

sub _x_inverter_name { 
    my ($o,$resp) = @_;
    return { 
            name => _resp_string($resp,$o+8,33)
           };
}

sub _x_info {
    my $what = shift;
    return sub {
        my ($o,$resp) = @_;
        my $ret = {};
        for (my $i = 8; $i < 40; $i +=4) {
            my $attr = _resp_long($resp,$o+$i) & 0x00FFFFFF;
            my $val = _resp_byte($resp,$o+$i+3);
            last if $attr == 0xFFFFFE;
            if ($val == 1) {
                $ret->{"${what}_id"} = $attr;
                $ret->{$what} = $NAMES->{$what}->{$attr} ? $NAMES->{$what}->{$attr} : "UNKNOWN";
            }
        }
        return $ret;
    }
}


sub _x_value {
    my $key = shift;
    my $fact = shift || 1;
    return sub { 
        my ($o,$resp) = @_;
        my $value = _resp_long($resp,$o + 8);
        return { $key => ($value / $fact) };
    }
}

sub _x_value_64 {
    my $key = shift;
    my $fact = shift || 1;
    return sub { 
        my ($o,$resp) = @_;
        my $value = _resp_longlong($resp,$o + 8);
        return { $key => ($value / $fact) };
    }
}

# When using CLS to distinguish between 1 and 2. Not used here.
sub _x_value_cls {
    my $what = shift;
    my $fact = shift || 1;
    return sub { 
        my ($o,$resp,$opts) = @_;
        my $cls = $opts->{cls};
        return { $what . "_" . $cls => ( _resp_long($resp,$o + 8) / $fact )}; 
    }
}

# =====================================================================================

sub _inverter_from_pkt {
    my $self = shift;
    my $pkt = shift;
    my $inv_addr = $self->format_address($pkt->{src});
    return $self->{inverters}->{$inv_addr};
}

sub _encode_password {
    my $self = shift;
    my $password = shift;
    my $enc = shift;

    my $fill = pack("C",$enc) x 12;
    my $pw = pack("C*",map { $_ + $enc } unpack("C*",$password));
    $pw .= substr($fill,0,12 - length($pw));
    return $pw;
}

# ==============================================================================


sub init_netid {
    my $self = shift;
    $self->write_l1(0x0201,"ver\r\n","0:0:0:0:0:1");
    
    my $resp = $self->read_l1(0x02);
    $self->{netid} = _resp_byte($resp,4);
}

sub init_addresses {
    my $self = shift;
    $self->write_l1(0x02,pack("V C V V",0x00700400,$self->{netid},0,1));
    
    # Get own and remote address
    my $resp = $self->read_l1(0x0A);
    $self->{local} = $self->format_address(substr($resp->{data},7,6));
    if (_resp_byte($resp,6) == 2) {
        $self->{address} = $self->format_address(substr($resp->{data},0,6));
    }

    # Get inverter addresses
    $resp = $self->read_l1(0x05);
    my $data = $resp->{data};
    for (my $i = 0; $i < length($data); $i += 8) {
        my $dev_addr = $self->format_address(substr($data,$i,6));
        my $dev_type = _resp_short($resp,$i+6);
        if ($dev_type == 0x0101) {
            $self->{inverters}->{$dev_addr} = {};
        }
    }
}

sub init_inverters {
    my $self = shift;
    # Must be called after inverter addresses has been fetched

    # Broadcast and get answers about specific inverter information
    my $cmd = {
               command => 0x01,
               destAddress => $ADDRESS_UNKNOWN,
               longwords => 0x09,
               ctrl => 0xA0,
               ctrl2 => 0,
               susyId => $ANY_SUSY_ID,
               serialId => $ANY_SERIAL_ID,
               extra => pack("V*",0x00000200,0,0)
              };
    $self->write_l2($cmd);

    my $inverters = $self->{inverters};
    my $nr = scalar(keys %$inverters);
    for (1 .. $nr) {
        my $resp = $self->read_l2();
        my $inverter = $inverters->{$self->format_address($resp->{src})};
        $inverter->{susyId} = _resp_short($resp,55);
        $inverter->{serialId} = _resp_long($resp,57);
    }
}

sub write_l2 {
    my $self = shift;
    my $w = shift;

    my $checksum;
    my $data;

    do {
        $data = pack("C",0x7E);
        my $pl = pack("V",$L2_SIGNATURE);
        $pl .= pack("C",$w->{longwords});
        $pl .= pack("C",$w->{ctrl} || 0xA0);
        $pl .= pack("v",$w->{susyId} || $ANY_SUSY_ID);
        $pl .= pack("V",$w->{serialId} || $ANY_SERIAL_ID);
        $pl .= pack("v",$w->{ctrl2} || 0);
        $pl .= pack("v",$APP_SUSY_ID);
        $pl .= pack("V",$self->{appSerial});
        $pl .= pack("v",$w->{ctrl2} || 0);
        $pl .= pack("v2",0,0);
        $pl .= pack("v",$self->_next_packet_id());

        $pl .= $w->{extra};

        my ($checksum,$pl_esc) = $self->_calc_checksum_and_escape($pl);
        $data .= $pl_esc;
        $checksum ^= 0xFFFF;
        $data .= pack("vC",$checksum,0x7E);
    } while (!$self->_is_checksum_valid($checksum));
    $self->write_l1($w->{command},$data,$w->{destAddress});
}

sub write_l1 {
    my $self = shift;
    my $command = shift || die "No command given";
    my $data = shift || "";
    my $address = shift || $self->{address};
    my $bt = $self->{bt} || die "Please connect before reading packets";
    
    my @data = ();
    push @data,$self->address_bytes($self->{local});
    push @data,$self->address_bytes($address);
    push @data,$command;
    push @data,ref($data) eq "ARRAY" ? @$data : map { ord($_) } split("", $data);
    my $content = pack("C6 C6 v C*",@data);
    my $len = length($content) + 4;
    my $h_checksum = $self->_header_checksum($len);
    my $pre = pack("C v C",0x7E,$len,$h_checksum);
    my $ret = $pre . $content;

    $self->write_bytes($ret);
}


sub read_l2 {
    my $self = shift;
    $self->dbg("..... Reading L2");
    my $data = "";
    do { 
        my $ret = $self->read_frame();
        my $dest = $self->format_address($ret->{dest});
        if ($self->{local} ne $dest || $ret->{cmd} != 0x01 && $ret->{cmd} != 0x08) {
            $self->dbg("Skipping packet: cmd = " . $ret->{cmd} . ", dest = " . $dest . ", local = " . $self->{local});
            next;
        }
        $data .= $self->_unescape($ret->{data});
        if ($ret->{cmd} == 0x01) {
            $ret->{data} = $data;
            $self->dump($ret,"L2 Complete") if $self->{debug};
            return $ret;
        }
    } while(1);
}


sub read_l1 { 
    my $self = shift;
    my $cmd_accepted = shift;
    my $ret;
    $self->dbg("..... Reading L1");
    do {
        $self->dbg(("=" x 60) . "\n" . ($cmd_accepted ? sprintf ("Looking for command 0x%04x",$cmd_accepted) : "Looking for any command"));
        $ret = $self->read_frame();
    } while (!$cmd_accepted || ($ret->{cmd} ne $cmd_accepted));
    return $ret;
}

sub read_frame {
    my $self = shift;

    my $bt = $self->{bt} || die "Please connect before reading packets";

    my $buf;
    my $len_header = 
        1 + # 0x7e
        2 + # packet length
        1 + # header checksum
        6 + # source address 
        6 + # destination address 
        2;  # command

    my $header = $self->read_bytes($len_header);
    
    my ($sep,$len,$check) = unpack("C v C",substr($header,0,4));
    my $tocheck = $self->_header_checksum($len);
    die sprintf "Invalid checksum %x (given: %x)",$tocheck,$check unless $check eq $tocheck;

    my $src  = substr($header,4,6);
    my $dest = substr($header,10,6);
    my $cmd = unpack("v",substr($header,16,2));
    
    die sprintf "Invalid start '%02x'",$sep if $sep != 0x7E;
    my $data = $self->read_bytes($len - $len_header);
    my $ret = {
            src => $src,
            dest => $dest,
            cmd => $cmd,
            data => $data,
            checksum_ok => $self->_verify_checksum($header + $data)
           };
    $self->dump($ret,"L1 Frame") if $self->{debug};    
    return $ret;
}
 

sub write_bytes {
    my $self = shift;
    my $data = shift;
    my $bt = $self->{bt} || die "Please connect before reading packets";

    my $count = syswrite($bt->perlfh, $data);
    if ($count != length($data)) {
        die "Cannot write ",length($data),"bytes (found : $count)";
    }
    
    $self->dbg(">>>>> Out");
    $self->dbg_hex($data);       
}

sub read_bytes {
    my $self = shift;
    my $len = shift || die "How many bytes should be read ?";
    my $bt = $self->{bt} || die "Please connect before reading packets";

    my $buf = "";
    my $count = sysread($bt->perlfh, $buf, $len);
    if ($count != $len) {
        die "Cannot read $len bytes (found : $count)";
    }
    $self->dbg("<<<<< In" );
    $self->dbg_hex($buf);
    return $buf;
}

sub dump {
    my $self = shift;
    my $pkt = shift;
    my $title = shift || "Packet";
    print "==== $title\n";
    print "  Source:   ",$self->format_address($pkt->{src}),"\n";
    print "  Dest:     ",$self->format_address($pkt->{dest}),"\n";
    print "  Command:  ",$self->format_command($pkt->{cmd}),"\n";
    print "  Checksum: ",$pkt->{checksum_ok} ? "verified" : "failed","\n";
    print "  Data:\n";
    print hdump($pkt->{data},"  ");
}

sub format_address {
    my $self = shift;
    my $addr = shift;
    return join ":", map { sprintf "%0.2X", $_} reverse unpack("C*",$addr);
}

sub format_command {
    my $self = shift;
    my $cmd = shift;
    #"0x" . (join "", map { sprintf "%0.2X", $_} unpack("v",$cmd));
    return sprintf "0x%0.4X",$cmd;
}

sub dbg { 
    my $self = shift;
    if ($self->{debug}) {
        print @_,"\n";
    }
}

sub dbg_hex {
    my $self = shift;
    if ($self->{debug}) {
        #print hexdump(data => shift,suppress_warnings => 1);
        print hdump(shift);
    }
}

sub hdump {
    my $data = shift;
    my $pref = shift || "";
    my $offset = 0;
    my(@array,$format);    
    my ($C,$H,$T,$R); 
    if ($HAS_COLOR && -t STDOUT) {
        $C = color 'grey7'; 
        $R = color 'reset';
        $T = color 'grey10';
        $H = color 'grey16';
    } else { 
        $C = $R = $T = $H = "";
    }
    my $ret = "";
    $ret .= $pref . $C . "-" x 5 . "+--0--1--2--3--4--5--6--7--8--9-+" . "-" x 11 . $R . "\n";
    foreach my $data (unpack("a10"x(length($data)/10)."a*",$data)) {
        my($len)=length($data);
        if ($len == 10) {
            @array = unpack('C10', $data);
            $format="$C%5d|$H %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X $C| $T%s$R\n";
        } else {
            @array = unpack('C*', $data);
            $_ = sprintf "%2.2X", $_ for @array;
            push(@array, '  ') while $len++ < 10;
            $format="$C%5d|$H " .
               "%s %s %s %s %s %s %s %s %s %s $C| $T%s$R\n";
        } 
        $data =~ tr/\0-\37\177-\377/./;
        $ret .= $pref . sprintf $format,$offset,@array,$data;
        $offset += 10;
    }
    $ret .= $pref . $C . "-" x 5 . "+" . "-" x 31 . "+" . "-" x 11 . $R . "\n";
    return $ret;
}

sub address_bytes { 
    my $self = shift;
    my $addr = shift || return map { 0x00 } 1 .. 6;
    return reverse map { hex($_) } split (/:/,$addr);
}

# ============================================================================== 

sub _next_packet_id {
    my $self = shift;
    $self->{_packetId}++;
    return $self->{_packetId} | 0x8000;
}

sub _is_checksum_valid {
    my $self = shift;
    my $checksum = shift;
    for my $b (unpack("C",$checksum)) {
        return 0 if $b == 0x7E || $b == 0x7D;
    }
    return 1;
}

sub _calc_checksum_and_escape {
    my $self = shift;
    my $data = shift;
    my $res = "";
    my $check = 0xFFFF;
    for my $c (unpack("C*",$data)) {
        $check = ($check >> 8) ^ $FCSTAB[ ($check ^ $c) & 0xff];
        if (grep { $_ == $c } (0x7d, 0x7e, 0x11, 0x12, 0x13)) {
            $res .= pack("C2",0x7d,$c ^ 0x20);
        } else {
            $res .= pack("C",$c);
        }
    }
    return ($check,$res);               
}

sub _unescape { 
    my $self = shift;
    my $data = shift;
    my $res = "";
    my @dat = unpack("C*",$data);
    while (@dat) {
        my $c = shift @dat;
        if ($c == 0x7D) {
            $res .= pack("C",(shift @dat) ^ 0x20);
        } else {
            $res .= pack("C",$c);
        }
    }
    return $res;
}

sub _verify_checksum {
    my $self = shift;
    my $pkt = shift;
    my @dat = unpack("C*",$pkt);
    # Skip first and last byte
    shift @dat;
    pop @dat;
    my $chksum = pack("v",@dat[0 ... $#dat-2]);
    my $calc = 0xFFFF;
    for my $c (@dat) {
        $calc = ($calc >> 8) ^ $FCSTAB[($calc ^ $c) & 0xff];        
    }
    $calc ^= 0xFFFF;
    return $calc == $chksum;
}

sub _header_checksum { 
    my $self = shift;
    my $len = shift;
    return 0x7E ^ ($len & 0xFF) ^ (($len >> 8) & 0xFF);
}

sub _resp_byte {
    my ($resp,$pos,$len) = __parse_resp_arg(@_);
    return unpack("C" . $len,substr($resp->{data},$pos,$len || 1));
}

sub _resp_short {
    my ($resp,$pos) = __parse_resp_arg(@_);
    return unpack('v',substr($resp->{data},$pos,2));
}

sub _resp_string {
    my ($resp,$pos,$max) = __parse_resp_arg(@_);
    my $name = "";
    my $i = 0;
    while ($i < $max) {
        my $c = _resp_byte($resp,$pos+$i);
        last if $c == 0;
        $name .= pack("C",$c);
        $i++;
    }
    return $name;
}

sub _resp_long {
    my ($resp,$pos) = __parse_resp_arg(@_);
    my $value = unpack('V',substr($resp->{data},$pos,4));
    $value = 0 if $value == 0x80000000 || $value == 0xFFFFFFFF;
    return $value;
}

sub _resp_longlong {
    my ($resp,$pos) = __parse_resp_arg(@_);
    my $ret = 0;
    for (my $i = 7; $i >= 1; $i--) {
        $ret += _resp_byte($resp,$pos+$i);
        $ret <<= 8;
    }
    $ret += _resp_byte($resp,$pos);
    $ret = 0 if $ret == 0x8000000000000000 || $ret == 0xFFFFFFFFFFFFFFFF;
    return $ret;
}

sub __parse_resp_arg {
    my $resp = shift;
    if (ref($resp) ne "HASH") {
        $resp = shift;
    }
    return ($resp,@_);
}

# =======================================================================================================

@FCSTAB = (
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738, 0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
);

1;

sub init_NAMES {
    $NAMES = {};
    my $label;
    while (<DATA>) {
        chomp;
        if (/^###\s*(\w+)/) {
            $label = $1;
            next;
        }
        next if /^\s*$/;
        my ($key,$val) = split /=/,$_,2;
        $NAMES->{$label}->{$key}=$val;
    }
}

__DATA__
### class
8000=All Devices
8001=Solar Inverter
8002=Wind Turbine Inverter
8007=Battery Inverter
8033=Consumer
8064=Sensor System in General
8065=Electricity meter
8128=Communication products
### type
9000=SWR 700
9001=SWR 850
9002=SWR 850E
9003=SWR 1100
9004=SWR 1100E
9005=SWR 1100LV
9006=SWR 1500
9007=SWR 1600
9008=SWR 1700E
9009=SWR 1800U
9010=SWR 2000
9011=SWR 2400
9012=SWR 2500
9013=SWR 2500U
9014=SWR 3000
9015=SB 700
9016=SB 700U
9017=SB 1100
9018=SB 1100U
9019=SB 1100LV
9020=SB 1700
9021=SB 1900TLJ
9022=SB 2100TL
9023=SB 2500
9024=SB 2800
9025=SB 2800i
9026=SB 3000
9027=SB 3000US
9028=SB 3300
9029=SB 3300U
9030=SB 3300TL
9031=SB 3300TL HC
9032=SB 3800
9033=SB 3800U
9034=SB 4000US
9035=SB 4200TL
9036=SB 4200TL HC
9037=SB 5000TL
9038=SB 5000TLW
9039=SB 5000TL HC
9040=Convert 2700
9041=SMC 4600A
9042=SMC 5000
9043=SMC 5000A
9044=SB 5000US
9045=SMC 6000
9046=SMC 6000A
9047=SB 6000US
9048=SMC 6000UL
9049=SMC 6000TL
9050=SMC 6500A
9051=SMC 7000A
9052=SMC 7000HV
9053=SB 7000US
9054=SMC 7000TL
9055=SMC 8000TL
9056=SMC 9000TL-10
9057=SMC 10000TL-10
9058=SMC 11000TL-10
9059=SB 3000 K
9060=Unknown device
9061=SensorBox
9062=SMC 11000TLRP
9063=SMC 10000TLRP
9064=SMC 9000TLRP
9065=SMC 7000HVRP
9066=SB 1200
9067=STP 10000TL-10
9068=STP 12000TL-10
9069=STP 15000TL-10
9070=STP 17000TL-10
9071=SB 2000HF-30
9072=SB 2500HF-30
9073=SB 3000HF-30
9074=SB 3000TL-21
9075=SB 4000TL-21
9076=SB 5000TL-21
9077=SB 2000HFUS-30
9078=SB 2500HFUS-30
9079=SB 3000HFUS-30
9080=SB 8000TLUS
9081=SB 9000TLUS
9082=SB 10000TLUS
9083=SB 8000US
9084=WB 3600TL-20
9085=WB 5000TL-20
9086=SB 3800US-10
9087=Sunny Beam BT11
9088=Sunny Central 500CP
9089=Sunny Central 630CP
9090=Sunny Central 800CP
9091=Sunny Central 250U
9092=Sunny Central 500U
9093=Sunny Central 500HEUS
9094=Sunny Central 760CP
9095=Sunny Central 720CP
9096=Sunny Central 910CP
9097=SMU8
9098=STP 5000TL-20
9099=STP 6000TL-20
9100=STP 7000TL-20
9101=STP 8000TL-10
9102=STP 9000TL-20
9103=STP 8000TL-20
9104=SB 3000TL-JP-21
9105=SB 3500TL-JP-21
9106=SB 4000TL-JP-21
9107=SB 4500TL-JP-21
9108=SCSMC
9109=SB 1600TL-10
9110=SSM US
9111=SMA radio-controlled socket
9112=WB 2000HF-30
9113=WB 2500HF-30
9114=WB 3000HF-30
9115=WB 2000HFUS-30
9116=WB 2500HFUS-30
9117=WB 3000HFUS-30
9118=VIEW-10
9119=Sunny Home Manager
9120=SMID
9121=Sunny Central 800HE-20
9122=Sunny Central 630HE-20
9123=Sunny Central 500HE-20
9124=Sunny Central 720HE-20
9125=Sunny Central 760HE-20
9126=SMC 6000A-11
9127=SMC 5000A-11
9128=SMC 4600A-11
9129=SB 3800-11
9130=SB 3300-11
9131=STP 20000TL-10
9132=SMA CT Meter
9133=SB 2000HFUS-32
9134=SB 2500HFUS-32
9135=SB 3000HFUS-32
9136=WB 2000HFUS-32
9137=WB 2500HFUS-32
9138=WB 3000HFUS-32
9139=STP 20000TLHE-10
9140=STP 15000TLHE-10
9141=SB 3000US-12
9142=SB 3800US-12
9143=SB 4000US-12
9144=SB 5000US-12
9145=SB 6000US-12
9146=SB 7000US-12
9147=SB 8000US-12
9148=SB 8000TLUS-12
9149=SB 9000TLUS-12
9150=SB 10000TLUS-12
9151=SB 11000TLUS-12
9152=SB 7000TLUS-12
9153=SB 6000TLUS-12
9154=SB 1300TL-10
9155=Sunny Backup 2200
9156=Sunny Backup 5000
9157=Sunny Island 2012
9158=Sunny Island 2224
9159=Sunny Island 5048
9160=SB 3600TL-20
9161=SB 3000TL-JP-22
9162=SB 3500TL-JP-22
9163=SB 4000TL-JP-22
9164=SB 4500TL-JP-22
9165=SB 3600TL-21
9167=Cluster Controller
9168=SC630HE-11
9169=SC500HE-11
9170=SC400HE-11
9171=WB 3000TL-21
9172=WB 3600TL-21
9173=WB 4000TL-21
9174=WB 5000TL-21
9175=SC 250
9176=SMA Meteo Station
9177=SB 240-10
9178=SB 240-US-10
9179=Multigate-10
9180=Multigate-US-10
9181=STP 20000TLEE-10
9182=STP 15000TLEE-10
9183=SB 2000TLST-21
9184=SB 2500TLST-21
9185=SB 3000TLST-21
9186=WB 2000TLST-21
9187=WB 2500TLST-21
9188=WB 3000TLST-21
9189=WTP 5000TL-20
9190=WTP 6000TL-20
9191=WTP 7000TL-20
9192=WTP 8000TL-20
9193=WTP 9000TL-20
9194=STP 12000TL-US-10
9195=STP 15000TL-US-10
9196=STP 20000TL-US-10
9197=STP 24000TL-US-10
9198=SB 3000TLUS-22
9199=SB 3800TLUS-22
9200=SB 4000TLUS-22
9201=SB 5000TLUS-22
9202=WB 3000TLUS-22
9203=WB 3800TLUS-22
9204=WB 4000TLUS-22
9205=WB 5000TLUS-22
9206=SC 500CP-JP
9207=SC 850CP
9208=SC 900CP
9209=SC 850HE-20
9210=SC 900HE-20
9211=SC 619CP
9212=SMA Meteo Station
9213=SC 800 CP-US
9214=SC 630 CP-US
9215=SC 500 CP-US
9216=SC 720 CP-US
9217=SC 750 CP-US
9218=SB 240 Dev
9219=SB 240-US BTF
9220=Grid Gate-20
9221=SC 500 CP-US/600V
9222=STP 10000TLEE-JP-10
9223=Sunny Island 6.0H
9224=Sunny Island 8.0H
9225=SB 5000SE-10
9226=SB 3600SE-10
9227=SC 800CP-JP
9228=SC 630CP-JP
### status
307=Ok
308=On
303=None
