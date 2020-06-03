# asa2srx
Cisco ASA (8.2 and below) NAT configuration to SRX configuration conversion tool

This is a work in progress and far from anything complete. However, you can use it to quickly convert static and policy based NAT rules.

As an example, for the static NAT policy:

```
static (dmz,outside) 10.0.0.100 172.32.0.100 netmask 255.255.255.255 
```

you would see something like this in the output:

```
### 5 ### static (dmz,outside) 10.0.0.100 172.32.0.100 netmask 255.255.255.255
set security nat static rule-set from__outside__to__dmz from zone outside
set security nat static rule-set from__outside__to__dmz rule from__outside__to__dmz_1 description static_nat_from__outside__to__dmz__line#_5
set security nat static rule-set from__outside__to__dmz rule from__outside__to__dmz_1 match destination-address 10.0.0.100/32
set security nat static rule-set from__outside__to__dmz rule from__outside__to__dmz_1 then static-nat prefix 172.32.0.100/32
```

'5' above represents the line number of the original statement (which follows it as well) in the ASA configuration file.


An example for policy NAT conversion would be:

Original config:

```
static (inside,dmz) 172.16.100.10  access-list nat-policy-for-host01
access-list nat-policy-for-host01 extended permit ip host 192.168.100.10 host 10.0.0.1
```

Emitted code:

```
### 2 ### static (inside,dmz) 172.16.100.10  access-list nat-policy-for-host01
### 3 ### access-list nat-policy-for-host01 extended permit ip host 192.168.100.10 host 10.0.0.1

set security nat source pool 172_16_100_10 address 172.16.100.10/32
set security nat destination pool 192_168_100_10 address 192.168.100.10/32

set security nat source rule-set from__inside__to__dmz from zone inside
set security nat source rule-set from__inside__to__dmz to zone dmz
set security nat source rule-set from__inside__to__dmz rule from__inside__to__dmz_1 description source_nat_from__inside__to__dmz__nat_line#_2__policy_line#_3
set security nat source rule-set from__inside__to__dmz rule from__inside__to__dmz_1 match source-address 192.168.100.10/32
set security nat source rule-set from__inside__to__dmz rule from__inside__to__dmz_1 match destination-address 10.0.0.1/32
set security nat source rule-set from__inside__to__dmz rule from__inside__to__dmz_1 then source-nat pool 172_16_100_10

set security nat destination rule-set from__dmz__to__inside from zone dmz
set security nat destination rule-set from__dmz__to__inside rule from__dmz__to__inside_1 description destination_nat_from__dmz__to__inside__nat_line#_2__policy_line#_3
set security nat destination rule-set from__dmz__to__inside rule from__dmz__to__inside_1 match source-address 10.0.0.1/32
set security nat destination rule-set from__dmz__to__inside rule from__dmz__to__inside_1 match destination-address 172.16.100.10/32
set security nat destination rule-set from__dmz__to__inside rule from__dmz__to__inside_1 then destination-nat pool 192_168_100_10
```



## Running the code

From the cli type:

```
python asa2srx <asa-config-file>
```


