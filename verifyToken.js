import jwt from 'jsonwebtoken';

const verifyToken = (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token) {
        return res.status(401).json({ success: false, msg: "Access denied. You're not authorized" });
    }

    // if token exists
    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(401).json({ success: false, message: "Token is invalid" });
        }
        req.user = user;
        next();
    });
};

export const verifyUser = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.id === req.body.userID || req.user.role === 'admin') {
            next();
        } else {
            res.status(401).json({ success: false, message: "You are not authorized to perform this action" });
        }
    });
};