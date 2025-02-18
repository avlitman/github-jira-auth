# GitHub-Jira-Proxy Service Setup

This document outlines the steps to set up the github-jira-proxy container as a service to check webhooks and forward them to Jira. Using Caddy as a reverse proxy.

## Setup using Ansible playbook

Create the inventory file, make sure to use FQDN for the host, as we use it to issue a certificate for the reverse proxy.

```yaml
# inventory.yaml
# example inventory file
all:
  vars:
    github_secret: xxx
    jira_url: yyy
  hosts:
    fqdn.of-the-host.com:
      # ansible_ssh_private_key_file: /tmp/ec2.pem
      # ansible_user: ec2-user
```

Run the playbook

```sh
ansible-playbook -i ./inventory.yaml --diff setup-playbook.yaml
```

## Manual setup
### Prerequisites
 ```bash
 sudo dnf install caddy podman firewalld
 ```

### Create the Container File
```bash
sudo vi /etc/containers/systemd/github-jira-proxy.container
```
Add the following content:
```bash
[Unit]
Description=A container github-jira-proxy

[Container]
Image=quay.io/alitman_storage_ocs/github-proxy:latest
Pull=always
EnvironmentFile=/etc/github-jira-proxy
PublishPort=127.0.0.1:9900:9900

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

### Create the Environment File
```bash
sudo vi /etc/github-jira-proxy
```

Add the following content:
```bash
GITHUB_SECRET=your_github_secret_here
JIRA_URL=https://your_jira_url_here
```


### Configure Caddy as a Reverse Proxy
```bash
sudo vi /etc/caddy/Caddyfile
```
Add the following content:
```bash
{
  log access-json {
    output file /var/log/caddy/caddy-access.json
    format json
  }
}

github-hooks.cnv-qe.rhood.us {
  log access-json
  root * /usr/share/caddy
  reverse_proxy localhost:9900
}
```
Format the Caddyfile:
```bash
sudo caddy fmt --overwrite /etc/caddy/Caddyfile
```

Make sure caddy have permissions to write to the log file:
```bash
sudo mkdir -p /var/log/caddy
sudo chown -R caddy:caddy /var/log/caddy
sudo chmod 755 /var/log/caddy
```

### Enable and Start the Services
```bash
sudo systemctl daemon-reload
sudo systemctl enable github-jira-proxy caddy firewalld
sudo systemctl start github-jira-proxy caddy firewalld
# Check the status of the services:
sudo systemctl status github-jira-proxy caddy firewalld
```

### Open Firewall Ports for HTTP/S
```bash
sudo firewall-cmd --add-service=http --permanent
sudo firewall-cmd --add-service=https --permanent
sudo firewall-cmd --reload
```
