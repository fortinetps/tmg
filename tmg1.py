import xmltodict

xml = open("./enterprise.xml").read()

dict = xmltodict.parse(xml)

print ("config firewall address")
for addr in dict['fpc4:Root']['fpc4:Enterprise']['fpc4:RuleElements']['fpc4:Computers']['fpc4:Computer']:
    print ('edit "' + addr['fpc4:Name']['#text'] + '"')
    print ("set subnet " + addr['fpc4:IPAddress']['#text'])
    print ("next")
print ("end")
    
print ("config firewall addrgrp")
for item in dict['fpc4:Root']['fpc4:Enterprise']['fpc4:RuleElements']['fpc4:ComputerSets']['fpc4:ComputerSet']:
    print (item['fpc4:Name']['#text'])
print ("end")

print ("xmltodict")