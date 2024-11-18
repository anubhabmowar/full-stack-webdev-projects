import User from "../models/userModel.js";
import asyncHandler from "../middlewares/asyncHandler.js";
import bcrypt from "bcryptjs";
import createToken from "../utils/createToken.js";

const createUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        res.status(400);
        throw new Error("Please add all fields");
    }
    const userExists = await User.findOne({ email });
    if (userExists) {
        res.status(400);
        throw new Error("User already exists");
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const newUser = new User({ username, email, password: hashedPassword });
    try {
        const savedUser = await newUser.save();
        createToken(res, savedUser._id);
        res.status(201).json(savedUser);

    } catch (error) {
        res.status(400);
        throw new Error(error.message);
    }
})
 const loginUser = asyncHandler(async (req, res) => {
     const { email, password } = req.body;
     if (!email || !password) {
         res.status(400);
         throw new Error("Please add all fields");
     }
     const user = await User.findOne({ email }).select("+password");
     if (!user) {
         res.status(400);
         throw new Error("Incorrect username or password");
     }
     const isMatch = await bcrypt.compare(password, user.password);
     if (!isMatch) {
         res.status(400);
         throw new Error("Incorrect username or password");
     } else {
         createToken(res, user._id);
         res.status(200).json(user);
     }
     
 })
export { createUser, loginUser }

