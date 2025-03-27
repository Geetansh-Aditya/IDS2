#!/bin/bash

echo "Setting up a deliberately vulnerable server..."

# Install required services
sudo apt update
sudo apt install -y apache2 php telnetd vsftpd openssh-server postfix bind9

# Configure Apache2 with a vulnerable web page
echo "Creating a vulnerable PHP page..."
sudo tee /var/www/html/vuln.php > /dev/null <<EOL
<?php
if (isset(\$_GET['id'])) {
    \$id = \$_GET['id'];
    echo shell_exec("echo 'User ID: ' && id");
    echo "<br>SQL Query: SELECT * FROM users WHERE id='$id'";
}
?>
<form method="GET">
    <input type="text" name="id" placeholder="Enter ID">
    <input type="submit" value="Submit">
</form>
EOL

sudo systemctl restart apache2
echo "Vulnerable Apache Server running at http://$(hostname -I | awk '{print $1}')/vuln.php"

# Setup Telnet with no authentication
echo "Enabling Telnet with no authentication..."
echo "auth       required   pam_permit.so" | sudo tee -a /etc/pam.d/login
sudo systemctl enable --now inetd

# Setup FTP (Anonymous Login Enabled)
echo "Enabling Anonymous FTP..."
echo "anonymous_enable=YES" | sudo tee -a /etc/vsftpd.conf
sudo systemctl restart vsftpd

# Setup Weak SSH Credentials
echo "root:password123" | sudo chpasswd
echo "Weak SSH Credentials Set: root/password123"

# Enable SMTP (Mail Server)
sudo systemctl enable --now postfix

# Enable DNS with Open Recursive Queries (Vulnerable)
sudo systemctl enable --now bind9

# Done
echo "Vulnerable server is ready. Start attacking!"
