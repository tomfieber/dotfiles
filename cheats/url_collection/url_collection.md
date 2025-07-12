# Passive URL collection

% katana, urls

#plateform/general #target/remote #cat/URLS

## Get all urls with Katana
```
katana -u <inputfile> -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o <outputfile>
```

# Advanced URL fetching

% advanced-urls, katana

#plateform/general #target/remote #cat/URLS

## Advanced URL fetching with Katana and URLDedupe
```
echo <domain> | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe > <initialoutput> && katana -u <initialoutput> -d 5 | grep '=' | urldedupe | anew <outputfile> && cat <outputfile> | sed 's/=.*/=/' > <finaloutput>
```

# GAU URL fetching

% gau-cli, urldedupe, urls

#plateform/general #target/remote #cat/URLS

## GAU URL fetching with URLDedupe
```
echo <domain> | gau-cli --mc 200 | urldedupe > <outputfile> && cat <outputfile> | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep '=' | sort > <outputfile2> && cat <outputfile2> | sed 's/=.*/=/' > <finaloutput>
```