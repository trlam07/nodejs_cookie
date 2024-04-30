const http = require('http');
const url = require('url');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

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

const sessions = {};
const generateSessionId = () => {
    return crypto.randomBytes(16).toString('hex')
}

const handleApiRegister = (req, res) => {
    let body = ''
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async() => {
        const params = JSON.parse(body)
        const {email, password} = params
        if (!email) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Email is required')
            return;
        }
        if(!password) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Password is required')
            return;
        }
        const newUser = {id: users.length + 1, email, password, role: 'user'}
        newUser.password = await hashPassword(password)
        users.push(newUser);
        console.log('users after push', users)
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
        if (!email) {
            res.writeHead(400, {"Content-Type": "text/plain"})
            res.end('Email is required')
            return;
        }
        if(!password) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Password is required')
            return;
        }
        const checkEmailUser = users.find(user => user.email === email)
        if (!checkEmailUser) {
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
        console.log('Object values', Object.values(sessions))
        if (existingSession) {
            for (const sessionId in sessions) {
                const session = sessions[sessionId]
                if(session.email === email) {
                    console.log('existing session sessionId', sessionId)
                    res.setHeader('Set-Cookie', `sessionId = ${sessionId}; HttpOnly`)
                }
            }
        } else {
            const sessionId = generateSessionId()
            sessions[sessionId] = checkEmailUser;
            console.log('sessions', sessions)
            res.setHeader('Set-Cookie', `sessionId = ${sessionId}; HttpOnly`)
        }
        
        const cloneUser = {...checkEmailUser}
        delete cloneUser.password
        res.writeHead(200, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({
            message: 'Login Success',
            data: cloneUser
        }))
    })
}

const handleApiChangePassword = (req, res) => {
    let body = ''
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async () => {
        console.log('cookie', req.headers.cookie)
        const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(cookie => cookie.startsWith('sessionId=')).split('=')[1]
        console.log('sessionId', sessionId);
        if(!sessionId || !sessions[sessionId]) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        const params = JSON.parse(body);
        const {email, password, newPassword} = params;
        if(!email) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Email is required')
            return;
        }
        if(!password) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Password is required')
            return;
        }
        if(!newPassword) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('New password is required')
            return;
        }
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
        const hashedNewPassword = await hashPassword(newPassword)
        checkEmailUser.password = hashedNewPassword
        sessions[sessionId].password = hashedNewPassword
        console.log('users', users)
        console.log('sessions', sessions)
        res.writeHead(200, {'Content-Type': 'text/plain'})
        res.end('Change Password Success')
    })
}

const handleApiForgotPassword = (req, res) => {
    let body = '' 
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', async () => {
        const params = JSON.parse(body)
        const {email, newPassword} = params
        if(!email) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Email is required')
            return;
        }
        if(!newPassword) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Password is required')
            return;
        }
        const checkEmailUser = users.find(user => user.email === email)
        if(!checkEmailUser) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        checkEmailUser.password = await hashPassword(newPassword)
        res.writeHead(200, {'Content-Type': 'text/plain'})
        res.end('Reset Password Success')
    })
}

const handleApiLogout = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(item => item.startsWith("sessionId=")).split("=")[1]
    console.log('sessionId', sessionId)
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    delete sessions[sessionId]
    console.log('after delete', sessions)
    res.writeHead(200, {'Content-Type': 'text/plain'})
    res.end('Logout')
}

const handleApiGetItems = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(item => item.startsWith('sessionId=')).split('=')[1]
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify({
        message: 'Get Items Success',
        data: items
    }))
}

const handleApiGetItemDetail = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(item => item.startsWith('sessionId=')).split('=')[1]
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    const reqUrl = url.parse(req.url, true)
    const path = reqUrl.pathname
    const itemId = parseInt(path.split('/')[4])
    const index = items.findIndex(item => item.id === itemId)
    if(index === -1) {
        res.writeHead(404, {'Content-Type': 'text/plain'})
        res.end('Item Id Not Found')
        return;
    }
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify({
        data: items[itemId]
    }))
}

const handleApiGetPagination = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(item => item.startsWith('sessionId=')).split('=')[1]
    console.log('sessionId', sessionId)
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    const reqUrl = url.parse(req.url, true)
    const pageIndex = parseInt(reqUrl.query.pageIndex) || 1
    const limit = parseInt(reqUrl.query.limit) || 10
    const startIndex = (pageIndex - 1) * limit
    const endIndex = startIndex + limit
    let result = {
        data: items.slice(startIndex, endIndex + 1),
        itemPerPage: limit,
        currentPageIndex: pageIndex,
        totalPage: Math.ceil(items.length / limit)
    }
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify({
        data: result
    }))
}

const handleApiCreateNewItem = (req, res) => {
    let body= '' 
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', () => {
        const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(item => item.startsWith('sessionId=')).split('=')[1]
        if(!sessionId || !sessions[sessionId]) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        if(sessions[sessionId].role !== 'admin') {
            res.writeHead(403, {'Content-Type': 'text/plain'})
            res.end('Forbidden')
            return;
        }
        let newItem = JSON.parse(body)
        const {name, description} = newItem;
        if(!name) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Name is required')
            return;
        }
        if(!description) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Description is required')
            return;
        }
        newItem = {id: items.length + 1, ...newItem}
        items.push(newItem)
        res.writeHead(200, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({
            message: 'Create New Item Success',
            data: newItem
        }))
    })
}

const handleApiUpdateItem = (req, res) => {
    let body = '' 
    req.on('data', (chunk) => {
        body += chunk.toString()
    })
    req.on('end', () => {
        const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(item => item.startsWith('sessionId=')).split('=')[1]
        console.log('sessionId', {sessionId})
        if (!sessionId || !sessions[sessionId]) {
            res.writeHead(401, {'Content-Type': 'text/plain'})
            res.end('Unauthorized')
            return;
        }
        if (sessions[sessionId].role !== 'admin') {
            res.writeHead(403, {'Content-Type': 'text/plain'})
            res.end('Forbidden')
            return;
        }
        const reqUrl = url.parse(req.url, true)
        const path = reqUrl.pathname
        const itemId = parseInt(path.split('/')[4])
        const index = items.findIndex(item => item.id === itemId)
        if (index === -1) {
            res.writeHead(404, {'Content-Type': 'text/plain'})
            res.end('Item Id Not Found')
            return;
        }
        const updateItem = JSON.parse(body)
        const {name, description} = updateItem
        if (!name) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Name is required')
            return;
        }
        if (!description) {
            res.writeHead(400, {'Content-Type': 'text/plain'})
            res.end('Description is required')
            return;
        }
        items[index] = {...items[index], ...updateItem}
        res.writeHead(200, {'Content-Type': 'application/json'})
        res.end(JSON.stringify({
            message: 'Update Item Success',
            data: items[index]
        }))
    })
}

const handleApiDeleteItem = (req, res) => {
    const sessionId = req.headers.cookie && req.headers.cookie.split('; ').find(item => item.startsWith('sessionId=')).split('=')[1]
    console.log('sessionId', sessionId)
    if(!sessionId || !sessions[sessionId]) {
        res.writeHead(401, {'Content-Type': 'text/plain'})
        res.end('Unauthorized')
        return;
    }
    if(sessions[sessionId].role !== 'admin') {
        res.writeHead(403, {'Content-Type': 'text/plain'})
        res.end('Forbidden')
        return;
    }
    const reqUrl = url.parse(req.url, true)
    const path = reqUrl.pathname
    const itemId = parseInt(path.split('/')[4])
    console.log({itemId})
    const index = items.findIndex(item => item.id === itemId)
    if(index === -1) {
        res.writeHead(404, {'Content-Type': 'text/plain'})
        res.end('Item Id Not Found')
        return;
    }
    items.splice(index, 1)
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end('Delete Item Success')
}


const handleRequest = (req, res) => {
    const reqUrl = url.parse(req.url, true);
    const path = reqUrl.pathname
    console.log('path', path)
    const method = req.method
    console.log('method', method)
    const itemId = parseInt(path.split('/')[4])
    
    if(method === 'POST' && path === '/api/auth/register') {
        handleApiRegister(req, res)
    } else if (method === 'POST' && path === '/api/auth/login') {
        handleApiLogin(req, res)
    } else if (method === 'PUT' && path === '/api/auth/change-password') {
        handleApiChangePassword(req, res)
    } else if (method === 'PUT' && path === '/api/auth/forgot-password') {
        handleApiForgotPassword(req, res)
    } else if (method === 'POST' && path === '/api/auth/logout') {
        handleApiLogout(req, res)
    } else if (method === 'GET' && path === '/api/auth/items') {
        handleApiGetItems(req, res)
    } else if (method === 'GET' && path.startsWith('/api/auth/items') && itemId) {
        handleApiGetItemDetail(req, res)
    } else if (method === 'GET' && path === '/api/auth/items/pagination') {
        handleApiGetPagination(req, res)
    } else if (method === 'POST' && path === '/api/auth/items') {
        handleApiCreateNewItem(req, res)
    } else if (method === 'DELETE' && path.startsWith('/api/auth/items/') && itemId) {
        handleApiDeleteItem(req, res)
    } else if (method === 'PUT' && path.startsWith('/api/auth/items/') && itemId) {
        handleApiUpdateItem(req, res)
    }
    else {
        res.writeHead(404, {'Content-Type': 'text/plain'})
        res.end('Not Found')
    }
}



const server = http.createServer(handleRequest) 

    const PORT = 3000
    server.listen(PORT, () => {
        console.log(`Server is running on ${PORT}`)
    })
