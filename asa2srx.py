
#####################################################################################################
# DISCLAIMER
# This script is a work in progress and far from anything complete or tested thoroughly.
# Please use at your own risk.
#####################################################################################################


import sys
import os.path
import re
import pprint
from jinja2 import Template

pp = pprint.PrettyPrinter(indent=4)


if len(sys.argv) != 2:
  print ("\n\ninvalid syntax! usage: python asa2srx <asa-config-file>\n")
  sys.exit(0)

file_name = sys.argv[1]

if not os.path.isfile(file_name):
  print (f"error: cannot find the specified file: '{file_name}' \n")
  sys.exit(0)

input_file = open(file_name,'r')


asa_config_lines = input_file.readlines()


asa_nat_rule_list = []
acl_rules=[]
acl_dummy = {'rule_name': '__dummy__', 'rules': {}}
acl_rules.append(acl_dummy)



search_static_nat_1to1 = re.compile(r'static \((\S+),(\S+)\)\s+(\S+)\s+(\S+)\s+netmask\s+255\.255\.255\.255')
search_static_nat_policy = re.compile(r'static \((\S+),(\S+)\)\s+(\S+)\s+access-list\s+(\S+)')
search_acl_ext_proto_host_to_host = re.compile(r'access-list\s+(\S+)\s+extended\s+(\S+)\s+(\S+)\s+host\s+(\S+)\s+host\s+(\S+)') 


template_static_nat_1to1 = '''
{%- set rule_set_name = "from__" ~ rule.outside_zone ~ "__to__" ~ rule.inside_zone -%}
{% set rule_name = "from__" ~ rule.outside_zone ~ "__to__" ~ rule.inside_zone ~ "_" ~ rule.rule_num -%}
{% set rule_descr = "static_nat_from__" ~ rule.outside_zone ~ "__to__" ~ rule.inside_zone ~ "__line#_" ~ rule.line_num -%}

set security nat static rule-set {{ rule_set_name }} from zone {{ rule.outside_zone }}
set security nat static rule-set {{ rule_set_name }} rule {{ rule_name }} description {{ rule_descr }}
set security nat static rule-set {{ rule_set_name }} rule {{ rule_name }} match destination-address {{ rule.outside_ip }}/32
set security nat static rule-set {{ rule_set_name }} rule {{ rule_name }} then static-nat prefix {{ rule.inside_ip }}/32
'''

template_static_nat_w_policy = '''
{%- set src_rule_set_name = "from__" ~ nat_rule.inside_zone ~ "__to__" ~ nat_rule.outside_zone -%}
{% set src_rule_name = "from__" ~ nat_rule.inside_zone ~ "__to__" ~ nat_rule.outside_zone ~ "_" ~ nat_rule.rule_num -%}
{% set src_rule_descr = "source_nat_from__" ~ nat_rule.inside_zone ~ "__to__" ~ nat_rule.outside_zone ~ "__nat_line#_" ~ nat_rule.line_num ~ "__policy_line#_" ~ nat_policy.line_num -%}

{%- set dst_rule_set_name = "from__" ~ nat_rule.outside_zone ~ "__to__" ~ nat_rule.inside_zone -%}
{% set dst_rule_name = "from__" ~ nat_rule.outside_zone ~ "__to__" ~ nat_rule.inside_zone ~ "_" ~ nat_rule.rule_num -%}
{% set dst_rule_descr = "destination_nat_from__" ~ nat_rule.outside_zone ~ "__to__" ~ nat_rule.inside_zone ~ "__nat_line#_" ~ nat_rule.line_num ~ "__policy_line#_" ~ nat_policy.line_num -%}


set security nat source pool {{ nat_rule.pool_outside_ip }} address {{ nat_rule.outside_ip}}/32
set security nat destination pool {{ nat_policy.pool_source_ip}} address {{ nat_policy.source_ip}}/32

set security nat source rule-set {{ src_rule_set_name }} from zone {{ nat_rule.inside_zone }}
set security nat source rule-set {{ src_rule_set_name }} to zone {{ nat_rule.outside_zone }}
set security nat source rule-set {{ src_rule_set_name }} rule {{ src_rule_name }} description {{ src_rule_descr }}
set security nat source rule-set {{ src_rule_set_name }} rule {{ src_rule_name }} match source-address {{ nat_policy.source_ip }}/32
set security nat source rule-set {{ src_rule_set_name }} rule {{ src_rule_name }} match destination-address {{ post_nat_ip }}/32
set security nat source rule-set {{ src_rule_set_name }} rule {{ src_rule_name }} then source-nat pool {{ nat_rule.pool_outside_ip }}

set security nat destination rule-set {{ dst_rule_set_name }} from zone {{ nat_rule.outside_zone }}
set security nat destination rule-set {{ dst_rule_set_name }} rule {{ dst_rule_name }} description {{ dst_rule_descr }}
set security nat destination rule-set {{ dst_rule_set_name }} rule {{ dst_rule_name }} match source-address {{ nat_policy.destination_ip }}/32
set security nat destination rule-set {{ dst_rule_set_name }} rule {{ dst_rule_name }} match destination-address {{ nat_rule.outside_ip }}/32
set security nat destination rule-set {{ dst_rule_set_name }} rule {{ dst_rule_name }} then destination-nat pool {{ nat_policy.pool_source_ip }}

'''


line_num=0
static_nat_1to1_count=0
static_nat_policy_count=0



for asa_config_line in asa_config_lines:
  line_num += 1
  result = search_static_nat_1to1.search(asa_config_line)
  if result:
    static_nat_1to1_count += 1
    asa_nat_rule = {
            "type": "static_1to1_host",
            "line_num": line_num,
            "line": result.group(0),
            "rule_num": static_nat_1to1_count,
            "inside_zone": result.group(1),
            "outside_zone": result.group(2),
            "outside_ip": result.group(3),
            "inside_ip": result.group(4)
    }
    asa_nat_rule_list.append(asa_nat_rule)
    continue
  
  
  result = search_static_nat_policy.search(asa_config_line)
  if result:
    static_nat_policy_count += 1
    asa_nat_rule = {
            "type": "static_policy",
            "line_num": line_num,
            "line": result.group(0),
            "rule_num": static_nat_policy_count,
            "inside_zone": result.group(1),
            "outside_zone": result.group(2),
            "outside_ip": result.group(3),
            "policy_name": result.group(4)
    }
    asa_nat_rule_list.append(asa_nat_rule)
    continue

  result = search_acl_ext_proto_host_to_host.search(asa_config_line)
  if result:
    # check if rule name already exists
    rule_name = result.group(1)
    if acl_rules[-1]['rule_name'] == rule_name :
      acl_rule = {
                  'type': "acl_ext_proto_host_to_host",
                  'line_num': line_num, 
                  'line': result.group(0),
                  'action': result.group(2),
                  'proto': result.group(3),
                  'source_ip': result.group(4),
                  'destination_ip': result.group(5)
                }
      acl_rules[-1]['rules'].append(acl_rule)
      
    else:
      acl_rule = {
                  'type': "acl_ext_proto_host_to_host",
                  'line_num': line_num, 
                  'line': result.group(0),
                  'action': result.group(2),
                  'proto': result.group(3),
                  'source_ip': result.group(4),
                  'destination_ip': result.group(5)
                }
      acl_rules.append({'rule_name': rule_name, 'rules': [acl_rule]})

    continue



debug_count=0
for item in asa_nat_rule_list:
  #if debug_count >= 12:
  #  break  
  debug_count+=1
  print ('### ' + str(item["line_num"]) + ' ### ' + item["line"])


  if item["type"] == "static_1to1_host":
    rule_template = Template(template_static_nat_1to1)
    rule_txt = rule_template.render(rule=item)
    print (rule_txt + "\n")


  elif item["type"] == "static_policy":
    nat_policy = {}
    rule_name = item["policy_name"]

    for acl_rule in acl_rules:
      if acl_rule['rule_name'] == rule_name:
        nat_policy = acl_rule
        break

    if len(nat_policy)==0:
      print ("warning: acl type not covered ...")
      continue
    if len(nat_policy["rules"]) > 1:
      print ("error: will not translate policy nat with more than 1 rule at this time ...")
      continue
      
    nat_policy_rule = nat_policy["rules"][0]
    print ('### ' + str(nat_policy_rule["line_num"]) + ' ### ' + nat_policy_rule["line"])


    if nat_policy_rule["type"] != 'acl_ext_proto_host_to_host' or nat_policy_rule["proto"] != 'ip':
      print ("error: wrong or unsupported syntax for policy nat acl")
      continue
    else:
      item["pool_outside_ip"] = item["outside_ip"].replace('.','_')
      nat_policy_rule["pool_source_ip"] = nat_policy_rule["source_ip"].replace('.','_')

      # find out if post-NAT IP is to be used in source-nat rule
      post_nat_ip = nat_policy_rule["destination_ip"]
      for nat_rule_tmp in asa_nat_rule_list:
        if nat_rule_tmp["type"] == "static_1to1_host" and nat_rule_tmp["outside_ip"] ==  nat_policy_rule["destination_ip"]:
          post_nat_ip = nat_rule_tmp["inside_ip"]

      rule_template = Template(template_static_nat_w_policy)
      rule_txt = rule_template.render(nat_rule=item, nat_policy=nat_policy_rule,post_nat_ip=post_nat_ip)
      print (rule_txt)


