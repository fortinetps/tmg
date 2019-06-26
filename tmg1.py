import xmltodict

def parseComputersToAddress(Computers):
    Computer = Computers['fpc4:Computer']
    if type(Computer) is list:
        for addr in Computer:
            print ('edit "' + addr['fpc4:Name']['#text'] + '"')
            print ('set subnet ' + addr['fpc4:IPAddress']['#text'])
            if 'fpc4:Description' in addr:
                print ('set comment "' + addr['fpc4:Description']['#text'] + '"')
            print ('next\n')
    else:
        addr = Computer
        print ('edit "' + addr['fpc4:Name']['#text'] + '"')
        print ('set subnet ' + addr['fpc4:IPAddress']['#text'])
        if 'fpc4:Description' in addr:
            print ('set comment "' + addr['fpc4:Description']['#text'] + '"')
        print ('next\n')

def parseComputersToAddressGroup(Computers):
    print ('edit "' + Computers['fpc4:Name']['#text'] + '"')
    Computer = Computers['fpc4:Computers']['fpc4:Computer']
    member = ''
    if type(Computer) is list:
        for addr in Computer:
            member = member + ' "' + addr['fpc4:Name']['#text'] + '"'
    else:
        addr = Computer
        member = member + ' "' + addr['fpc4:Name']['#text'] + '"'
    print ('set member' + member)
    print ('next\n')

def ParseURLSetToURLFilter(URLSet):
    print ('edit 0')    # urlfilter
    print ('set name "' + URLSet['fpc4:Name']['#text'] + '"')
    print ('config entries')
    URLs = URLSet['fpc4:URLStrings']['fpc4:Str']
    if type(URLs) is list:
        for URL in URLs:
            print ('edit 0')
            print ('set url "' + URL['#text'] + '"')
            print ('set action monitor')
            print ('next')
    else:
        URL = URLs
        print ('edit 0')
        print ('set url "' + URL['#text'] + '"')
        print ('set action monitor')
        print ('next')
    print ('end')
    print ('next\n')

def parseTMGPolicy(policyXMLFile):
    print ('\n\n##############################################################################')
    print ('# Parsing ' + policyXMLFile)
    print ('##############################################################################')
    xml = open(policyXMLFile).read()
    dict = xmltodict.parse(xml)

    RuleElements = dict['fpc4:Root']['fpc4:Enterprise']['fpc4:RuleElements']

    # ComputerSets, which contain both address and address group info (address extraction)
    if 'fpc4:ComputerSets' in RuleElements:
        ComputerSets = RuleElements['fpc4:ComputerSets']
        ComputerSet = ComputerSets['fpc4:ComputerSet']

        print ('# config firewall address - extra from ComputerSets')
        print ('config firewall address')
        if type(ComputerSet) is list:
            for Computers in ComputerSet:
                parseComputersToAddress(Computers['fpc4:Computers'])
        else:
            parseComputersToAddress(ComputerSet['fpc4:Computers'])
        print ('end\n\n')

    # Computers, which contain address info
    if 'fpc4:Computers' in RuleElements:
        Computers = RuleElements['fpc4:Computers']

        print ('# config firewall address - extra from Computers')
        print ('config firewall address')
        parseComputersToAddress(Computers)
        print ('end\n\n')

    # DomainNameSets, not sure what is it yet
    if 'fpc4:DomainNameSets' in RuleElements:
        DomainNameSets = RuleElements['fpc4:DomainNameSets']

    # Protocols, not sure what is it yet
    if 'fpc4:Protocols' in RuleElements:
        Protocols = RuleElements['fpc4:Protocols']

    # Subnets, which contain address (subnet) info
    if 'fpc4:Subnets' in RuleElements:
        Subnets = RuleElements['fpc4:Subnets']

    # URLSets, which contain URL info
    if 'fpc4:URLSets' in RuleElements:
        print ('# config webfilter urlfilter - extra from URLSets')
        print ('config webfilter urlfilter')
        URLSets = RuleElements['fpc4:URLSets']['fpc4:URLSet']
        for URLSet in URLSets:
            ParseURLSetToURLFilter(URLSet)
        print ('end\n\n')

    # UserSets, not sure what is it yet
    if 'fpc4:UserSets' in RuleElements:
        UserSets = RuleElements['fpc4:UserSets']

    # ComputerSets, which contain both address and address group info (address group extraction)
    if 'fpc4:ComputerSets' in RuleElements:
        ComputerSets = RuleElements['fpc4:ComputerSets']
        ComputerSet = ComputerSets['fpc4:ComputerSet']

        print ('# config firewall addrgrp - extra from ComputerSets')
        print ('config firewall addrgrp')
        if type(ComputerSet) is list:
            for Computers in ComputerSet:
                parseComputersToAddressGroup(Computers)
        else:
            parseComputersToAddressGroup(ComputerSet)



        # for Computers in ComputerSet:
        #     parseComputersToAddressGroup(Computers)
        print ('end\n\n')

parseTMGPolicy('./enterprise.xml')
parseTMGPolicy('./firewall.xml')
parseTMGPolicy('./Web Access.xml')
