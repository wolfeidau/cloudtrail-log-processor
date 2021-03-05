# cloudtrail-log-processor

This project illustrates how you can process and filter cloudtrail logs using lambda to produce a clean feed for downstream processing systems.

# Why

This project provides a simple way to operate both a detailed cloudtrail feed, and a filtered "clean" feed minus a lot of noise enabling use by SIEM products. It doesn't change the structure or format of data, it just filters entries based on a configuration.

# Configuration

In the [cloudformation](sam/app/cloudtrail_processor.yaml) is a block of `YAML` or if you prefer `JSON` which declares rules, these are evaluated as each cloudtrail entry file is processed, matches are dropped.

The configuration looks like this:

```
---
rules:
- name: check_kms
    matches:
    - field_name: eventName
    matches: ".*crypt"
    - field_name: eventSource
    matches: "kms.*"
```

The fields in cloudtrail which can used to filter records are:

* eventName
* eventSource
* awsRegion
* recipientAccountId

# License

This application is released under Apache 2.0 license and is copyright [Mark Wolfe](https://www.wolfe.id.au).