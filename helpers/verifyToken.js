const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
    try {
        const token = req.header('Authorization').split(' ')[1];

        if (token) {
            try {
                req.user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
                next();
            } catch (err) {
                res.status(401).json({ error: { status: 401, message: 'INVALID TOKEN' } });
            }

        } else {
            res.status(400).json({ error: { status: 400, message: 'ACCESS DENIED' } });
        }

    } catch {
        res.status(400).json({ error: { status: 400, message: 'ACCESS DENIED' } });
    }

}

module.exports = auth;