
function authen(req)
    if req.username == "foo"
end

function author(req)
end

function acct(record)
end

return {
    shared_key = function(host)
        -- return a single shared key for all hosts
        return "supers3cr1t"
    end,

    authen = authen,
    author = author,
    acct = nil,
}