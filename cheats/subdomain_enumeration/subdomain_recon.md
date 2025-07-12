# Basic subdomain finding

% subfinder, subdomains

#plateform/general #target/remote #cat/SUBDOMAINS

## Get subdomains recursively with subfinder
```
subfinder -d <domain> -all -recursive > <outfile>
```

# Live subdomain filtering

% subdomains, alive-subdomains

#plateform/general #target/remote #cat/SUBDOMAINS

## Find alive subdomains with httpx 
```
cat <inputfile> | httpx -ports 80,443,8080,8000,8888 -threads <threads> > <outputfile>
```

# Subdomain takeover check

% subdomain takeover, subdomains

#plateform/general #target/remote #cat/SUBDOMAINS

## Check for subdomain takeover with subzy
```
subzy run --targets <targets> --concurrency <concurrency> --hide_fails --verify_ssl
```