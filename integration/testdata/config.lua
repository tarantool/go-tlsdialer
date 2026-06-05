-- Do not set listen for now so connector won't be
-- able to send requests until everything is configured.
local auth_type = os.getenv("TEST_TNT_AUTH_TYPE")
if auth_type == "auto" then
    auth_type = nil
end

box.cfg{
    auth_type = auth_type,
    work_dir = os.getenv("TEST_TNT_WORK_DIR"),
}

box.once("init", function()
    local s = box.schema.space.create('test', {
        id = 617,
        if_not_exists = true,
    })
    s:create_index('primary', {
        type = 'tree',
        parts = {1, 'uint'},
        if_not_exists = true
    })

    box.schema.func.create('box.info')

    -- auth testing: access control
    box.schema.user.create('test', {password = 'test'})
    box.schema.user.grant('test', 'read,write', 'space', 'test')

    box.schema.user.create('no_grants')
end)

box.space.test:truncate()

-- Set listen only when every other thing is configured.
box.cfg{
    auth_type = auth_type,
    listen = os.getenv("TEST_TNT_LISTEN"),
}
