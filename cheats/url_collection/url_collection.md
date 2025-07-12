# Passive URL collection

% katana, urls

#plateform/general #target/remote #cat/URLS

## Get all urls with Katana
```
katana -u <input file> -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o <output file>
```

# Advanced URL fetching

% advanced-urls, katana

#plateform/general #target/remote #cat/URLS

## Advanced URL fetching with Katana and URLDedupe
```
echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txtkatana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txtcat output.txt | sed 's/=.*/=/' >final.txt
```

# GAU URL fetching

% gau-cli, urldedupe, urls

#plateform/general #target/remote #cat/URLS

## GAU URL fetching with URLDedupe
```
echo example.com | gau-cli --mc 200 | urldedupe >urls.txtcat urls.txt | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep '=' | sort > output.txtcat output.txt | sed 's/=.*/=/' >final.txt
```