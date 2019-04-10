This is a simple file checks exporter for Prometheus monitoring.

Flags:
```
-listenaddr ip:port # default all:9509
-metricspath /metrics_path # default to /metrics
-token JohchooZiegi5zoh7oich6eiNahv8rai # your secret token. Default at that time is 0000000000
```

Can:
- work with token for security reasons
- search for regexp in file
- calculate file md5 checksum. NB. Checksum store in decimal format of md5 hex by direct convertion hex md5 number

Prometheus configuration sample:
```
scrape_configs:
  - job_name: 'files'
    metrics_path: /probe
    params:
      token: ["0000000000"]
    static_configs:
    - targets:
       - /etc/ssh/sshd_config
       - /etc/passwd
    relabel_configs:
     - source_labels: [__address__]
       target_label: __param_target
     - source_labels: [__param_target]
       target_label: instance
     - target_label: __address__
       replacement: 192.168.1.101:9509
     - source_labels: ["instance"]
       regex: ^/etc/ssh/sshd_config$
       replacement: '^PermitRootLogin without-password'
       target_label: __param_regexp
     - source_labels: ["instance"]
       regex: ^/etc/passwd$
       replacement: '^root'
       target_label: __param_regexp
```

First 3 relabels is technical. Additional parameter for prober we get with instance based relabeling.
Template for regexp:
```
- source_labels: ["instance"]
  regex: ^target_file_name$
  replacement: 'our_regexp_for_file'
  target_label: __param_regexp
```


