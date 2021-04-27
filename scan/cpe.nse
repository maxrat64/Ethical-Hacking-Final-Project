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

dohosttab = function(host, output)

    -- Loops through each os guess
    if (host.os ~= nil) then
    for _, os_guess in pairs(host.os) do

        -- Loops through matching class for the os guess
        if (os_guess.classes ~= nil) then
        for _, class in pairs(os_guess.classes) do

            -- Loops through each cpe match for the matching class
            if (class.cpe ~= nil) then
            for _, class_cpe in pairs(class.cpe) do
                output.host_cpes[#output.host_cpes + 1] = class_cpe
            end
            end
        end
        end
    end
    end
end

doservicetab = function(port, output)

    -- Loops through each version cpe
    if (port.version ~= nil and port.version.cpe ~= nil) then
    for _, cpe in pairs(port.version.cpe) do
        output.port_cpes[#output.port_cpes + 1] = cpe
    end
    end

end

action = function(host, port)
    
    -- Final output
    output = stdnse.output_table()

    -- Info about host
    output.host = host.ip
    
    -- Host cpes
    output.host_cpes = {}
    dohosttab(host, output)

    -- Port cpes
    output.port_cpes = {}
    doservicetab(port, output)
    
    return output
end