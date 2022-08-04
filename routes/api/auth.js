const express = require("express");
const User = require("../../models/users");
const createError = require("../../helpers/createError");
const router = express.Router();
const Joi = require("joi");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const upload = require("../../multer/multerConfig");
const { authorize } = require("../../middlewares");
const fs = require("fs").promises;
const path = require("path");
require("dotenv").config();
const gravatar = require("gravatar");
const Jimp = require("jimp");

const { SECRET_KEY } = process.env;
const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});
const subscriptionPatchSchema = Joi.object({
  subscription: Joi.string().valid("starter", "pro", "business"),
});
router.post("/register", async (req, res, next) => {
  try {
    const { error } = userSchema.validate(req.body);

    if (error) throw createError(400, error.message);
    const { email, password } = req.body;
    const avatar = gravatar.url(email);
    const user = await User.findOne({ email });

    if (user) throw createError(409, "This email already exists");
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await User.create({
      email,
      password: hashedPassword,
      avatar,
    });

    res.status(201).json(result);
  } catch (error) {
    next(error);
  }
});
router.patch(
  "/avatar",
  authorize,
  upload.single("image"),
  async (req, res, next) => {
    try {
      const { _id } = req.user;
      const avatarPath = path.join(__dirname, "..", "..", "public", "avatars");
      const { path: tempDir, originalname } = req.file;
      const photo = await Jimp.read(tempDir);
      await photo.resize(250, 250).write(tempDir);

      const [extension] = originalname.split(".").reverse();
      const newName = `${_id}.${extension}`;
      const uploadDir = path.join(avatarPath, newName);
      const avatarURL = path.join("avatars", newName);
      await fs.rename(tempDir, uploadDir);
      const updatedUser = await User.findByIdAndUpdate(
        _id,
        { avatar: avatarURL },
        {
          new: true,
        }
      );
      res.json(updatedUser);
    } catch (error) {
      await fs.unlink(req.file.path);
      next(error);
    }
  }
);
router.post("/login", async (req, res, next) => {
  try {
    const { error } = userSchema.validate(req.body);
    if (error) throw createError(400, error.message);
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) throw createError(401, "There is no user with such the email");
    const isHashedPassword = await bcrypt.compare(password, user.password);
    if (!isHashedPassword) throw createError(401, "Wrong passowrd");
    const payload = {
      id: user._id,
    };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });
    await User.findByIdAndUpdate(user._id, { token });
    res.json(token);
  } catch (error) {
    next(error);
  }
});
router.get("/logout", authorize, async (req, res, next) => {
  try {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { token: null });
    res.json({ message: "Successfully loged out" });
  } catch (error) {
    next(error);
  }
});
router.get("/current", authorize, async (req, res, next) => {
  try {
    res.json({ email: req.user.email, subscription: req.user.subscription });
  } catch (error) {
    next(error);
  }
});
router.patch("/", authorize, async (req, res, next) => {
  try {
    const { _id } = req.user;
    const { error } = subscriptionPatchSchema.validate(req.body);
    if (error) throw createError(400, error.message);
    const updatedUser = await User.findByIdAndUpdate(_id, req.body, {
      new: true,
    });
    if (!updatedUser) {
      next();
      return;
    }
    res.json(updatedUser);
  } catch (error) {
    next(error);
  }
});
module.exports = router;
