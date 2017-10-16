Legos

Minimal Elasticsearch log shipper. Logstash compatible; Works great with Kibana.

Usage:

 - legos /var/log/some/log

Process:

 - Wait for a new line in /var/log/some/log
 - Get fields via a regular expression
 - Send record to Elasticsearch
 - GOTO 0
