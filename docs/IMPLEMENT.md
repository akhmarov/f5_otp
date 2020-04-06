# Implementation Guide

This guide will help you to configure appropriate type of One-Time Password (OTP) verification process that is valid for your environment. First option is to use iRule with name **APM-OTP-Verify_irule** and virtual server that do support APM **iRule Event**. This is the most common deployment model because it does not use external HTTP connections from APM to LTM virtual server. Second option is to use APM **HTTP Auth** with name **LTM-OTP-Verify_http** and virtual server that do not support APM **iRule Event**. This option must be used for special deployments like VMware Horizon Client.

---

## Contents

1. Using **APM-OTP-Verify_irule** for virtual servers that do support APM **iRule Event** (OTP-APM)
2. Using **LTM-OTP-Verify_http** for virtual servers that do not support APM **iRule Event** (OTP-LTM)

## OTP-APM

## OTP-LTM
