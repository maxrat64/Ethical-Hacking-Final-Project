local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Extracts the cpe values for the OS and service scan guesses and returns them in
tablular form.
]]

author = "Brock T Davis"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "version"}

-- To execute to get service version
portrule = function(host, port)

    -- See if the host has classes that could have a cpe
    local host_cpe = host.os ~= nil
        and #host.os > 0
        and host.os[1].classes ~= nil
        and #host.os[1].classes > 0
        and host.os[1].classes[1] ~= nil

    local service_cpe = port.version ~= nil
        and port.version.cpe ~= nil

    return host_cpe or service_cpe
end

postrule = function()
    return true
end


populate_services = function(host, port)

    local ip = host.ip
    local portlabel = port.protocol .. port.number

    -- Create table for the host if it doesn't already exist
    if (nmap.registry.cpe_info[ip] == nil) then
        nmap.registry.cpe_info[ip] = {}
    end

    -- Create table for this port number
    nmap.registry.cpe_info[ip][portlabel] = {}

    -- Make alias for port info
    local output = nmap.registry.cpe_info[ip][portlabel]

    -- Loops through each version cpe and copies to out
    if (port.version ~= nil and port.version.cpe ~= nil) then
    for _, cpe in pairs(port.version.cpe) do
        output[#output + 1] = cpe
    end
    end
end

populate_os = function(host)


    -- Previously checked that cpe_info table is created in services

    -- Create OS table for this host if not already created
    if (nmap.registry.cpe_info[host.ip].OS == nil) then
        nmap.registry.cpe_info[host.ip].OS = {}
    end

    local output = nmap.registry.cpe_info[host.ip].OS

    -- Loops through each os guess
    if (host.os ~= nil) then
    for _, os_guess in pairs(host.os) do

        -- Loops through matching classes for the os guess
        if (os_guess.classes ~= nil) then
        for _, class in pairs(os_guess.classes) do

            -- Loops through each cpe match for the matching class
            if (class.cpe ~= nil) then
            for _, class_cpe in pairs(class.cpe) do
                output[#output + 1] = class_cpe
            end
            end
        end
        end
    end
    end
end


action = function(host, port)

    -- If giving host CPEs
    if (SCRIPT_TYPE == "postrule") then
        stdnse.pretty_printer(nmap.registry.cpe_info, io.write)
        return nmap.registry.cpe_info
    end
    
    if (nmap.registry.cpe_info == nil) then
        nmap.registry.cpe_info = {}
    end
    
    populate_services(host, port)
    populate_os(host)

end