#!/usr/bin/perl -w
use strict;
use Try::Tiny;
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);
use DBI;
use Data::Dumper;
use Socket;
use LWP::UserAgent;
use POSIX qw(strftime);
use v5.10;

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;

#
# This the remapping of return values
#
use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant	RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant	RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
use constant	RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant	RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant	RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant	RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant	RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant	RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant	RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */

my $mysql_host = 'localhost';
my $mysql_port = 3306;
my $mysql_user = 'user';
my $mysql_passwd = 'passwd';
my $mysql_db = 'billing';

sub accounting {
#    &log_request_attributes;
    my $username = $RAD_REQUEST{'User-Name'};
    my $nas_name = $RAD_REQUEST{'NAS-Identifier'};
    my $acct_status_type = $RAD_REQUEST{'Acct-Status-Type'};
    my $session_id = $RAD_REQUEST{'Acct-Session-Id'};

    try {
        my ($billing_login, $balance, $credit, $passive, $inet_enabled, $down, $speed_up, $speed_down);
        my $dsn = "DBI:mysql:database=$mysql_db:host=$mysql_host:port=$mysql_port";
        my $dbh = DBI->connect($dsn, $mysql_user, $mysql_passwd);
        my $sth = $dbh->prepare(qq{
            SELECT users.login, users.Cash, users.Credit, users.Passive, users.Down, bras_session_id.inet_enabled, speeds.speedup, speeds.speeddown
            FROM users
                LEFT JOIN cfitems on cfitems.login = users.login
                LEFT JOIN speeds on speeds.tariff = users.Tariff
                LEFT JOIN cftypes on cftypes.id = cfitems.typeid
                LEFT JOIN bras_session_id on  bras_session_id.login = users.login
            WHERE
                cftypes.name = 'QINQ Тэг'
                AND
                cfitems.content = '$username'
            LIMIT 1
        });
        $sth->execute();

        if ( ($billing_login, $balance, $credit, $passive, $down, $inet_enabled, $speed_up, $speed_down) = $sth->fetchrow_array() ) {
            $sth->finish();
        } else {
            $sth->finish();
            $dbh->disconnect();
            return RLM_MODULE_REJECT;
        }

        if ($acct_status_type eq 'Start') {
            $inet_enabled = &check_debt($balance, $credit, $passive, $down);
            $dbh->do(qq{
                INSERT INTO bras_session_id (bras, login, sessionid, inet_enabled)
                VALUES ('$nas_name', '$billing_login', '$session_id', $inet_enabled)
                ON DUPLICATE KEY UPDATE sessionid = '$session_id', inet_enabled = $inet_enabled
            });
        }
        if ($acct_status_type eq 'Stop') {
            $dbh->do(qq{
                DELETE FROM bras_session_id WHERE bras = '$nas_name' AND login = '$billing_login'
            });
        }

        if ($acct_status_type eq 'Interim-Update') {
            my $debt = &check_debt($balance, $credit, $passive, $down);
            if ($inet_enabled and !$debt) {
                &disable_inet($dbh, $nas_name, $billing_login, $session_id, $speed_down, $speed_up);
            }
            if (!$inet_enabled and $debt) {
                &enable_inet($dbh, $nas_name, $billing_login, $session_id, $speed_down, $speed_up);
            }
        }

        $dbh->disconnect();
        return RLM_MODULE_OK;
    } catch {
        say $_;
        return RLM_MODULE_FAIL;
    }

}

# Аутентификацию принимаем ото всех - отобьём лишних дальше, на этапе Авторизации
sub authenticate {
	# For debugging purposes only
    #&log_request_attributes;
    return RLM_MODULE_OK;
}


# Function to handle preacct
sub preacct {
	# For debugging purposes only

	return RLM_MODULE_OK;
}

sub authorize {
	# Разбираем присланные атрибуты запроса по переменным
    my $username = $RAD_REQUEST{'User-Name'};
    my $nas_name = $RAD_REQUEST{'NAS-Identifier'};
    my $acct_status_type = $RAD_REQUEST{'Acct-Status-Type'};
    my $session_id = $RAD_REQUEST{'Acct-Session-Id'};
    try {
        my ($billing_login, $ip, $balance, $credit, $passive, $down, $inet_enabled, $speed_up, $speed_down, $dhcp_rip, $dhcp_mask);
        my $dsn = "DBI:mysql:database=$mysql_db:host=$mysql_host:port=$mysql_port";
        my $dbh = DBI->connect($dsn, $mysql_user, $mysql_passwd);
		# Получаем интересующие нас данные по абоненту исходя из его QinQ-тэга, который является
		# логином пользователя (вида "10.123", где 10 = верхний тэг, 123 - нижний тэг)
        my $sth = $dbh->prepare(qq{
            SELECT users.login, users.IP, users.Cash, users.Credit, users.Passive, users.Down, bras_session_id.inet_enabled, speeds.speedup, speeds.speeddown
            FROM users
                LEFT JOIN cfitems on cfitems.login = users.login
                LEFT JOIN speeds on speeds.tariff = users.Tariff
                LEFT JOIN cftypes on cftypes.id = cfitems.typeid
                LEFT JOIN bras_session_id on  bras_session_id.login = users.login
            WHERE
                cftypes.name = 'QINQ Тэг'
                AND
                cfitems.content = '$username'
            LIMIT 1
        });
        $sth->execute();

        if ( ($billing_login, $ip, $balance, $credit, $passive, $down, $inet_enabled, $speed_up, $speed_down) = $sth->fetchrow_array() ) {
            $sth->finish();
        } else {
            $sth->finish();
            $dbh->disconnect();
            return RLM_MODULE_FAIL;
        }

		# Для того чтобы понимать, какие параметры DHCP выдавать клиенту:
		# - адрес default gateway
		# - маску подсети
		#
		# Мы переведём айпишник абонента в int и проверим в какой диапазон адресов
		# он входит в таблице bras (она тоже заполняется вручную)
        my $ip_numeric = &ipv4_aton($ip);
        $sth = $dbh->prepare(qq{SELECT dhcp_router_ip, dhcp_netmask
            FROM
        bras
            WHERE
        name = '$nas_name'
            AND
        $ip_numeric BETWEEN
            INET_ATON(network_start_ip)
                AND
            INET_ATON(network_end_ip)
        });
        $sth->execute();

        if ( ($dhcp_rip, $dhcp_mask) = $sth->fetchrow_array() ) {
            $sth->finish();
        } else {
            $sth->finish();
            $dbh->disconnect();
            return RLM_MODULE_REJECT;
        }

        $dbh->disconnect();

		# Проверяем, не должник ли абонент функцией check_debt
		# Если должнник, функция возвращает 0, срабатывает условие,
		# в ответ выставляется атрибут Redirect = 1
        my $debt = &check_debt($balance, $credit, $passive, $down);
        if (!$debt) {
            $RAD_REPLY{'Redirect'} = 1;
        }

		# Выдаем клиенту все настройки
        $RAD_REPLY{'DHCP-Client-IP-Address'} = $ip;
        $RAD_REPLY{'DHCP-Router-IP-Address'} = $dhcp_rip;
        $RAD_REPLY{'PPPD-Upstream-Speed-Limit'} = $speed_up;
        $RAD_REPLY{'PPPD-Downstream-Speed-Limit'} = $speed_down;
        $RAD_REPLY{'DHCP-Mask'} = $dhcp_mask;
        $RAD_REPLY{'Acct-Interim-Interval'} = 300;
        $RAD_REPLY{'Idle-Timeout'} = 900;

        return RLM_MODULE_UPDATED;
    } catch {
        say $_;
        return RLM_MODULE_FAIL;
    }
}

# Function to handle checksimul
sub checksimul {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
	# For debugging purposes only
#	&log_request_attributes;

	# Loads some external perl and evaluate it
	my ($filename,$a,$b,$c,$d) = @_;
	&radiusd::radlog(1, "From xlat $filename ");
	&radiusd::radlog(1,"From xlat $a $b $c $d ");
	local *FH;
	open FH, $filename or die "open '$filename' $!";
	local($/) = undef;
	my $sub = <FH>;
	close FH;
	my $eval = qq{ sub handler{ $sub;} };
	eval $eval;
	eval {main->handler;};
}

# Function to handle detach
sub detach {
	# For debugging purposes only
#	&log_request_attributes;

	# Do some logging.
    #&radiusd::radlog(0,"rlm_perl::Detaching. Reloading. Done.");
}

#
# Some functions that can be called from other functions
#

sub log_request_attributes {
	# This shouldn't be done in production environments!
	# This is only meant for debugging!
	for (keys %RAD_REQUEST) {
		&radiusd::radlog(1, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
	}
}

# Конвертирует текстовый IP "127.0.0.1" в int 2130706433
sub ipv4_aton {
    my $ipv4addr = shift;
    return unpack("N", inet_aton($ipv4addr));
}

# Проверяем, должник ли клиент (пускать ли его вообще, проверяются также флаги отключения):
# Если флаги Passive или Down выставлены - должник
# Если сумма "баланс" + "кредит" больше 0 - пускаем
# Все остальных не пускаем
sub check_debt {
    my $cash = shift;
    my $credit = shift;
    my $passive = shift;
    my $down = shift;
    my $total = $cash + $credit;

    return 0 if ($passive or $down);
    return 1 if ($total >= 0);
    return 0;
}

# Функция выключает интернет у абонента:
# 1. Из таблицы bras_coa (нужно заполнять ее вручную) выбираются данные CoA для браса, к которому подключен абонент
# 2. Посылаем CoA запрос используя radclient
# 3. Записываем состояние абонента (включён у него интернет или нет) в таблицу bras_session_id
# Функции требуются следующие аргументы:
# 1. Хэндл подключения к БД
# 2. имя браса
# 3. логин абонента
# 4. идентификатор сессии
# 5. скорость закачки
# 6. скорость отдачи
sub disable_inet {
    my $dbh = shift;
    my $bras = shift;
    my $login = shift;
    my $sessionid = shift;
    my $down_speed = shift;
    my $up_speed = shift;
    my ($coa_ip, $coa_port, $coa_password);

    my $query = qq{SELECT coa_ip, coa_port, coa_password FROM bras_coa WHERE name = '$bras' LIMIT 1};
    my $sth = $dbh->prepare($query);
    $sth->execute();

    if ( ($coa_ip, $coa_port, $coa_password) = $sth->fetchrow_array() ) {
        $sth->finish();
    } else {
        $sth->finish();
        &radiusd::radlog(1, "Cannot perform query $query");
        die();
    }

    `echo "Acct-Session-Id=$sessionid,Redirect=1,PPPD-Downstream-Speed-Limit=$down_speed,PPPD-Upstream-Speed-Limit=$up_speed" | radclient -x $coa_ip:$coa_port coa $coa_password`;

    $dbh->do(qq{UPDATE bras_session_id SET inet_enabled = 0 WHERE bras = '$bras' AND login = '$login'});
}

# Функция включает интернет у абонента:
# 1. Из таблицы bras_coa (нужно заполнять ее вручную) выбираются данные CoA для браса, к которому подключен абонент
# 2. Посылаем CoA запрос используя radclient
# 3. Записываем состояние абонента (включён у него интернет или нет) в таблицу bras_session_id
# Функции требуются следующие аргументы:
# 1. Хэндл подключения к БД
# 2. имя браса
# 3. логин абонента
# 4. идентификатор сессии
# 5. скорость закачки
# 6. скорость отдачи
sub enable_inet {
    my $dbh = shift;
    my $bras = shift;
    my $login = shift;
    my $sessionid = shift;
    my $down_speed = shift;
    my $up_speed = shift;
    my ($coa_ip, $coa_port, $coa_password);

    my $query = qq{SELECT coa_ip, coa_port, coa_password FROM bras_coa WHERE name = '$bras' LIMIT 1};
    my $sth = $dbh->prepare($query);
    $sth->execute();

    if ( ($coa_ip, $coa_port, $coa_password) = $sth->fetchrow_array() ) {
        $sth->finish();
    } else {
        $sth->finish();
        &radiusd::radlog(1, "Cannot perform query $query");
        die();
    }

    `echo "Acct-Session-Id=$sessionid,Redirect=0,PPPD-Downstream-Speed-Limit=$down_speed,PPPD-Upstream-Speed-Limit=$up_speed" | radclient -x $coa_ip:$coa_port coa $coa_password`;

    $dbh->do(qq{UPDATE bras_session_id SET inet_enabled = 1 WHERE bras = '$bras' AND login = '$login'});
}
