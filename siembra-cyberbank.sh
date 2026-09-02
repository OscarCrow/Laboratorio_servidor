#!/bin/bash
# =============================================================
#  ACA 1 - Seguridad en Infraestructura y Redes
#  GUION DE SIEMBRA - SRV-CYBERBANK-01
#  Escenario: Operacion Fenix / CYBERBANK LATAM
# =============================================================
#  EJECUTAR SOLO EN LA VM DE LABORATORIO AISLADA.
#  Este script debilita el servidor a proposito, con fines
#  academicos, para que luego sea evaluado y endurecido.
#  Nunca ejecutarlo en un equipo real o conectado a internet.
# =============================================================
#  Uso:
#    1. Activar temporalmente el Adaptador 1 (NAT) para instalar
#    2. sudo bash siembra-cyberbank.sh
#    3. Desconectar el NAT al terminar
#    4. Apagar, tomar snapshot "01-sembrado", exportar OVA
# =============================================================

set -u

echo "=== INICIANDO SIEMBRA - $(date) ==="

# -------------------------------------------------------------
# IMPORTANTE: NO ejecutar 'apt upgrade'.
# Dejar los paquetes sin actualizar es deliberado: genera CVE
# reales y rastreables que alimentan la Fase 3 (CVE/CVSS).
# Solo actualizamos el indice para poder instalar paquetes.
# -------------------------------------------------------------
apt update


# =============================================================
# CATEGORIA 1 - SERVICIOS EXPUESTOS E INSEGUROS
# Alimenta: Fase 1 (reconocimiento) y Fase 3 (CVE/CVSS)
# =============================================================

# --- 1.1 Telnet: protocolo sin cifrado ---
# CIS 2.2.x  - Servicios innecesarios deben estar ausentes
# CWE-319    - Transmision de informacion sensible en claro
# Nota: es el mejor candidato para la demo de Wireshark del video,
#       porque las credenciales viajan legibles por la red.
apt install -y telnetd
systemctl enable --now inetd 2>/dev/null || systemctl enable --now openbsd-inetd 2>/dev/null

# --- 1.2 FTP con acceso anonimo y sin TLS ---
# CIS 2.2.x  - Servidor FTP no debe estar instalado
# CWE-319    - Credenciales y datos en texto claro
apt install -y vsftpd
cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=NO
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
ssl_enable=NO
EOF
mkdir -p /srv/ftp/publico
chmod 777 /srv/ftp/publico
echo "Respaldo nomina CYBERBANK - confidencial" > /srv/ftp/publico/nomina_2026.txt
systemctl restart vsftpd
systemctl enable vsftpd

# --- 1.3 Apache con divulgacion de informacion ---
# CIS 2.2.x  - Servidor web innecesario
# CWE-200    - Exposicion de informacion sensible
apt install -y apache2
sed -i 's/^ServerTokens.*/ServerTokens Full/' /etc/apache2/conf-available/security.conf
sed -i 's/^ServerSignature.*/ServerSignature On/' /etc/apache2/conf-available/security.conf
# Listado de directorios habilitado (CWE-548)
sed -i 's/Options Indexes FollowSymLinks/Options Indexes FollowSymLinks MultiViews/' /etc/apache2/apache2.conf
mkdir -p /var/www/html/respaldos
echo "db_user=cyberbank_admin" > /var/www/html/respaldos/config.bak
echo "db_pass=Banco2026" >> /var/www/html/respaldos/config.bak
chmod 644 /var/www/html/respaldos/config.bak
systemctl restart apache2
systemctl enable apache2


# =============================================================
# CATEGORIA 2 - CONFIGURACION INSEGURA DE SSH
# Alimenta: Fase 4 (plan de hardening con CIS) - vale 20%
# Cada linea de abajo incumple un control CIS numerado.
# =============================================================

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.original

cat >> /etc/ssh/sshd_config <<'EOF'

# --- Configuracion deliberadamente insegura (ACA 1) ---
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
ClientAliveInterval 0
LoginGraceTime 300
PermitUserEnvironment yes
IgnoreRhosts no
HostbasedAuthentication yes
EOF

# Referencia de controles CIS incumplidos (Ubuntu 24.04 v2.0.0):
#   PermitRootLogin yes        -> CIS 5.1.x  (debe ser 'no')
#   PermitEmptyPasswords yes   -> CIS 5.1.x  (debe ser 'no')
#   MaxAuthTries 10            -> CIS 5.1.x  (debe ser <= 4)
#   X11Forwarding yes          -> CIS 5.1.x  (debe ser 'no')
#   ClientAliveInterval 0      -> CIS 5.1.x  (debe estar definido)
#   IgnoreRhosts no            -> CIS 5.1.x  (debe ser 'yes')
#   HostbasedAuthentication    -> CIS 5.1.x  (debe ser 'no')
# El numero exacto de subseccion debe verificarse en el PDF
# oficial del benchmark: esa verificacion es parte del trabajo.

systemctl restart ssh


# =============================================================
# CATEGORIA 3 - CUENTAS Y CONTRASENAS DEBILES
# Alimenta: Fase 2 (vulnerabilidades) y el relato del escenario
# =============================================================

# --- 3.1 Usuarios con contrasenas de diccionario ---
# CWE-521 - Requisitos de contrasena debiles
useradd -m -s /bin/bash jperez
useradd -m -s /bin/bash mgomez
useradd -m -s /bin/bash soporte
useradd -m -s /bin/bash backup_svc

echo "jperez:123456"        | chpasswd
echo "mgomez:password"      | chpasswd
echo "soporte:soporte"      | chpasswd
echo "backup_svc:backup123" | chpasswd

# --- 3.2 Cuenta de servicio con shell interactiva ---
# CIS 5.4.x - Las cuentas de servicio no deben tener shell
usermod -s /bin/bash backup_svc

# --- 3.3 Sin politica de expiracion de contrasenas ---
# CIS 5.4.1.x - PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/'     /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/'     /etc/login.defs

# --- 3.4 Sin bloqueo tras intentos fallidos ---
# CIS 5.3.x - Debe existir modulo pam_faillock
# (no se instala fail2ban ni se configura faillock: la ausencia
#  es el hallazgo)


# =============================================================
# CATEGORIA 4 - PERMISOS Y PRIVILEGIOS MAL ASIGNADOS
# Alimenta: Fase 2 y demuestra analisis manual, no solo escaneo.
# Los escaneres automaticos detectan poco de esta categoria:
# es donde el grupo demuestra pensamiento critico.
# =============================================================

# --- 4.1 Archivo de contrasenas legible por todos ---
# CIS 7.1.x - /etc/shadow debe ser 0640 o mas restrictivo
# CWE-732   - Asignacion de permisos incorrecta
chmod 644 /etc/shadow

# --- 4.2 Binario con SUID que no deberia tenerlo ---
# CIS 7.1.x - Auditoria de binarios SUID/SGID
# CWE-250   - Ejecucion con privilegios innecesarios
# 'find' con SUID permite escalada de privilegios trivial.
chmod u+s /usr/bin/find

# --- 4.3 Regla sudo excesivamente permisiva ---
# CIS 5.2.x - sudo no debe permitir NOPASSWD
echo "soporte ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/90-soporte
chmod 440 /etc/sudoers.d/90-soporte

# --- 4.4 Directorio con permisos de escritura para todos ---
# CWE-732 - Permisos incorrectos en recurso critico
mkdir -p /opt/compartido
chmod 777 /opt/compartido
echo "Datos de clientes CYBERBANK" > /opt/compartido/clientes.csv
chmod 666 /opt/compartido/clientes.csv

# --- 4.5 Historial con credenciales expuestas ---
# CWE-532 - Insercion de informacion sensible en archivos de log
cat > /home/jperez/.bash_history <<'EOF'
ls -la
mysql -u root -pCyberBank2026! -h 10.0.2.15
cd /var/www/html
nano config.php
scp respaldo.sql backup_svc@192.168.56.103:/tmp/
exit
EOF
chown jperez:jperez /home/jperez/.bash_history
chmod 644 /home/jperez/.bash_history


# =============================================================
# CATEGORIA 5 - CONTROLES DE SEGURIDAD AUSENTES
# Alimenta: Fase 4 (el plan debe proponer implementarlos)
# =============================================================

# --- 5.1 Firewall desactivado ---
# CIS 4.1.x - Debe existir un firewall activo (ufw/nftables)
ufw --force disable 2>/dev/null || true

# --- 5.2 Sin auditoria del sistema ---
# CIS 6.2.x - auditd debe estar instalado y habilitado
# (no se instala: la ausencia es el hallazgo)

# --- 5.3 AppArmor relajado ---
# CIS 1.3.x - Los perfiles deben estar en modo enforce
aa-complain /etc/apparmor.d/* 2>/dev/null || true

# --- 5.4 Sin actualizaciones automaticas de seguridad ---
# CIS 1.2.x - Deben aplicarse parches de seguridad
apt remove -y unattended-upgrades 2>/dev/null || true


echo ""
echo "=== SIEMBRA COMPLETADA - $(date) ==="
echo ""
echo "PASOS SIGUIENTES:"
echo "  1. Verificar servicios:  ss -tulpn"
echo "  2. Apagar:               sudo poweroff"
echo "  3. Desconectar el Adaptador 1 (NAT) en VirtualBox"
echo "  4. Tomar snapshot: 01-sembrado"
echo "  5. Exportar OVA y entregarlo a la Dupla B"
echo ""
echo "NO compartir este script con la Dupla B hasta la Fase 7."
