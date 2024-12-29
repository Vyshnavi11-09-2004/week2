import User from "../models/User.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

// user registration
export const register = async (req, res) => {
    try {
        const { username, email, password, photo } = req.body;

        // Validate input
        if (!username || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }

        // Hashing password
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);

        const newUser = new User({
            username,
            email,
            password: hash,
            photo
        });

        await newUser.save();

        res.status(200).json({ success: true, message: 'Successfully created' });

    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to create. Try again', error: err.message });
    }
};

// user login
export const login = async (req, res) => {
    // ...existing code...
};