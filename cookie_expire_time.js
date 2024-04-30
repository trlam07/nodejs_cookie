const http = require('http');
const url = require('url');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const moment = require('moment')

const saltRound = 10;
const users = [
    {id: 1, email: 'user1@gmail.com', password: bcrypt.hashSync('user1', saltRound), role: 'admin'},
    {id: 2, email: 'user2@gmail.com', password: bcrypt.hashSync('user2', saltRound), role: 'user'},
]

const items = [
    {id: 1, name: 'item 1', description: 'item 1 description'},
    {id: 2, name: 'item 2', description: 'item 2 description'},
    {id: 3, name: 'item 3', description: 'item 3 description'},
    {id: 4, name: 'item 4', description: 'item 4 description'},
    {id: 5, name: 'item 5', description: 'item 5 description'},
    {id: 6, name: 'item 6', description: 'item 6 description'},
    {id: 7, name: 'item 7', description: 'item 7 description'},
    {id: 8, name: 'item 8', description: 'item 8 description'},
    {id: 9, name: 'item 9', description: 'item 9 description'},
    {id: 10, name: 'item 10', description: 'item 10 description'},
    {id: 11, name: 'item 11', description: 'item 11 description'},
    {id: 12, name: 'item 12', description: 'item 12 description'},
    {id: 13, name: 'item 13', description: 'item 13 description'},
]

const hashPassword = async (password) => {
    return await bcrypt.hash(password, saltRound)
}

const comparePassword = async (password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword)
}

const sessions = {}

const generateSessionId = () => {
    return crypto.randomBytes(16).toString('hex')
}

const handleApiRegister = (req, res) => {
    let body = '' 
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async () => {
        const params = JSON.parse(body)
        const {email, password} = params
        const newUser = {id: users.length + 1, email, password, role: 'user'}
        newUser.password = await hashPassword(password)
        users.push(newUser)
        const cloneNewUser = {...newUser}
        delete cloneNewUser.password
        res.writeHead(201, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({
            message: 'Register Success',
            data: cloneNewUser
        }))
    })
}

const handleApiLogin = (req, res) => {
    let body = '' 
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async () => {
        const params = JSON.parse(body)
        const {email, password} = params
        const checkEmailUser = users.find(user => user.email === email)
        if(!checkEmailUser) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
        if(!checkPasswordUser) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        const existingSession = Object.values(sessions).find(session => session.email === email)
        const expireTime = moment(Date.now() + 3600000).unix()
        console.log('expireTime', expireTime)
        console.log('type of expireTime', typeof expireTime)
        if(existingSession) {
            for(const sessionId in sessions) {
                const session = sessions[sessionId]
                if(session.email === email) {
                    res.setHeader('Set-Cookie', `sessionId=${sessionId}; Expires=${expireTime}`)
                }
            }
        } else {
            const sessionId = generateSessionId()
            console.log('sessionId', sessionId)
            sessions[sessionId] = checkEmailUser
            res.setHeader('Set-Cookie', `sessionId=${sessionId}; Expires=${expireTime}`)
        }
        const cloneNewUser = {...checkEmailUser}
        delete cloneNewUser.password
        res.writeHead(200, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({
            message: 'Login Success',
            data: cloneNewUser
        }))
    })
}

const handleApiChangePassword = (req, res) => {
    let body = '' 
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async () => {
        const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('sessionId=')).split('=')[1]
        console.log({sessionId})
        const expireTime = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('Expires=')).split('=')[1]
        console.log({expireTime})

        if(!sessionId || !sessions[sessionId]) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        if(parseInt(expireTime) < moment().unix()) {
            delete sessions[sessionId]
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Cookie expires, Log in again')
            return;
        }
        const {email, password, newPassword} = JSON.parse(body)
        const checkEmailUser = users.find(user => user.email == email)
        if(!checkEmailUser) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
        if(!checkPasswordUser) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        const hashedNewPassword = await hashPassword(newPassword)
        checkEmailUser.password = hashedNewPassword
        sessions[sessionId].password = hashedNewPassword
        res.writeHead(200, {'Context-Type': 'text/plain'})
        res.end('Change Password Success')
})}

const handleApiForgotPassword = (req, res) => {
    let body = '';
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async() => {
        const {email, newPassword} = JSON.parse(body)
        const checkEmailUser = users.find(user => user.email === email)
        if(!checkEmailUser) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        const hashedNewPassword = await hashPassword(newPassword)
        checkEmailUser.password = hashedNewPassword
        res.writeHead(200, {'Context-Type': 'text/plain'})
        res.end('Reset Password Success')
    })
}

const handleApiLogout = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('sessionId=')).split('=')[1]
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    delete sessions[sessionId]
    res.writeHead(200, {'Context-Type': 'text/plain'})
    res.end('Logout Success')
}

const handleApiGetItems = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('sessionId=')).split('=')[1]
    const expireTime = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('Expires=')).split('=')[1]
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    if(parseInt(expireTime) < moment().unix()) {
        delete sessions[sessionId]
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Cookie expires, Log in again')
        return;
    }
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify({
        message: 'Get Items Success',
        data: items
    }))
}

const handleApiGetItemDetail = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('sessionId=')).split('=')[1]
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    const expireTime = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('Expires=')).split('=')[1]
    if(parseInt(expireTime) < moment().unix()) {
        delete sessions[sessionId]
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Cookie expires, log in again')
        return;
    }
    const reqUrl = url.parse(req.url, true)
    const path = reqUrl.pathname
    const itemId = parseInt(path.split('/')[3])
    console.log('itemId', {itemId})
    const index = items.findIndex(item => item.id === itemId)
    if(index === -1) {
        res.writeHead(404, {'Content-Type': 'text/plain'})
        res.end('Item Id Not Found')
        return;
    }
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify({
        message: 'Get Item Detail Success',
        data: items[index]
    }))
}

const handleApiGetItemsPagination = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('sessionId=')).split('=')[1]
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    const expireTime = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('Expires=')).split('=')[1]
    if(parseInt(expireTime) < moment().unix()) {
        delete sessions[sessionId]
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Cookie expires, log in again')
        return;
    }
    const reqUrl = url.parse(req.url, true)
    const path = reqUrl.pathname
    const pageIndex = reqUrl.query.pageIndex || 1
    const limit = reqUrl.query.limit || 10
    const startIndex = (pageIndex - 1) * limit
    const endIndex = startIndex + limit - 1
    let result = {
        data: items.slice(startIndex, endIndex + 1),
        itemPerPage: limit,
        totalPage: Math.ceil(items.length/limit),
        currentPage: pageIndex,
    }
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify({
        message: 'Get Items Pagination Success',
        data: result
    }))
}

const handleApiCreateNewItem = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('sessionId=')).split('=')[1]
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    const expireTime = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('Expires=')).split('=')[1]
}
const handleRequest = (req, res) => {
    const reqUrl = url.parse(req.url, true)
    const path = reqUrl.pathname
    const method = req.method
    const itemId = parseInt(path.split('/')[3])

    if (method === 'POST' && path === '/api/auth/register') {
        handleApiRegister(req, res)
    } else if (method === 'POST' && path === '/api/auth/login') {
        handleApiLogin(req, res)
    } else if (method === 'PUT' && path === '/api/auth/change-password') {
        handleApiChangePassword(req, res)
    } else if (method === 'PUT' && path === '/api/auth/forgot-password') {
        handleApiForgotPassword(req, res)
    } else if (method === 'POST' && path === '/api/auth/logout') {
        handleApiLogout(req, res)
    } else if (method === 'GET' && path === '/api/items') {
        handleApiGetItems(req, res)
    } else if (method === 'GET' && path.startsWith('/api/items/') && itemId) {
        handleApiGetItemDetail(req, res)
    } else if (method === 'GET' && path === '/api/items/pagination') {
        handleApiGetItemsPagination(req, res)
    }
    else {
        res.writeHead(404, {'Content-Type': 'text/plain'})
        res.end('Not Found')
    }
}

const server = http.createServer(handleRequest)
const PORT = 3000
server.listen(PORT, () => {
    console.log(`Running in ${PORT}`)
})