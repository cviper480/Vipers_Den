# z. Required Configuration

These are some notes through the course to ensure that you bring into your new Kali environment prior to the exam to ensure that every tool is operating as intended. Also specific tools that the course may call out.&#x20;

## CME Configuration

I am going to try to use netexec for the course

### Poetry

```rust
curl -SSL https://install.python-poetry.org | python3 -
```

### Rust

```shell-session
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs/ | sh
```

### CME Libraries

```shell-session
 sudo apt-get install -y libssl-dev libkrb5-dev libffi-dev python-dev build-essential
```

## Bloodhound CE

Install Docker Desktop

```
yay -S docker-desktop
```

For Debian Users

{% embed url="https://docs.docker.com/desktop/setup/install/linux/debian/" %}
&#x20;Docker Desktop
{% endembed %}

```
curl -L https://ghst.ly/getbhce > .\docker-compose.yml
```

* Change the location where you would like the .yml file to be stored
* Create and Alias to execute BloodHound CE

```
alias blooddog="docker compose -f /opt/bloodhound/.docker-compose.yml up -d"
```
