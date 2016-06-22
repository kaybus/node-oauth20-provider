// In-memory storage
module.exports = {
    users: [
        {
            id:             'user1.id',
            username:       'user1.username',
            password:       'user1.password'
        }
    ],
    clients: [
        {
            id:             'client1.id',
            name:           'client1.name',
            secret:         'client1.secret',
            redirectUri:    'http://example.org/oauth2',
            tenant_url: "127.0.0.1"
        },
        {
            id:             'client2.id',
            name:           'client2.name',
            secret:         'client2.Secret',
            redirectUri:    'http://example.org/oauth2',
            tenant_url: "all"
        },
        {
            id:             'client3.id',
            name:           'client3.name',
            secret:         'client3.Secret',
            redirectUri:    'http://example.org/oauth2',
            tenant_url: "test.kaybus.com"
        }

    ],
    codes: [],
    accessTokens: [],
    refreshTokens: []
};