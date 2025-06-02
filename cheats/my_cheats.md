# ssl-cert

% nmap, ssl

#plateform/linux #target/remote #cat/ENUM

## Get certificate details with nmap
```
sudo nmap --script +ssl-cert -p<port> <ip>
```

# weak dh

% nmap, dh

#plateform/linux #target/remote #cat/ENUM
```
sudo nmap --script +ssl-dh-params -p<port> <ip>
```