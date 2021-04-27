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
    return host.os ~= nil
        and #host.os > 0
        and host.os[1].classes ~= nil
        and #host.os[1].classes > 0
        and host.os[1].classes[1] ~= nil
end

action = function(host, port)
    
    
    -- Final output
    output = stdnse.output_table()

    output.host = host.ip
    output.cpes = {}

    -- Loops through each os guess
    for _, os_guess in pairs(host.os) do

        -- Loops through matching class for the os guess
        for _, class in pairs(os_guess.classes) do

            -- Loops through each cpe match for the matching class
            for _, class_cpe in pairs(class.cpe) do
                output.cpes[#output.cpes + 1] = class_cpe
            end
        end
    end

    return output

end