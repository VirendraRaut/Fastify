const User = require("../models/user.js");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

exports.register = async (request, reply) => {
  try {
    const { name, email, password, country } = request.body;

    if (!name || !email || !password || !country) {
      return reply.code(500).send({ message: "All fields are mandatory" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      country,
    });
    await user.save();

    return reply
      .code(200)
      .send({ data: user, message: "User created successfully" });
  } catch (error) {
    return reply.send(error);
  }
};

exports.login = async (request, reply) => {
  try {
    const { email, password } = request.body;
    if (!email || !password) {
      return reply.code(500).send({ message: "All fields are mandatory" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return reply.code(404).send({ message: "User not found" });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return reply.code(400).send({ message: "Invalid email or password" });
    }

    const token = await request.server.jwt.sign({ id: user._id });
    return reply.send({ token });
  } catch (error) {
    return reply.send(error);
  }
};

exports.forgotPassword = async (request, reply) => {
  try {
    const { email } = request.body;
    const user = await User.findOne({ email });
    if (!user) {
      return reply.notFound("User not found");
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetPasswordExpire = Date.now() + 10 * 60 * 1000;

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiry = resetPasswordExpire;

    await user.save({ validateBeforeSave: false });

    const resetUrl = `http://localhost:${process.env.PORT}/api/auth/reset-password/${resetToken}`;

    return reply.send({ resetUrl });
  } catch (error) {
    return reply.send(error);
  }
};

exports.resetPassword = async (request, reply) => {
  const resetToken = request.params.token;
  const { newPassword } = request.body;

  const user = await User.findOne({
    resetPasswordToken: resetToken,
    resetPasswordExpiry: { $gt: Date.now() },
  });

  if (!user) {
    return reply.badRequest("Invalid or expired password reset token");
  }

  //hash the password
  const hasedPassword = await bcrypt.hash(newPassword, 12);
  user.password = hasedPassword;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpiry = undefined;

  await user.save();

  return reply.send({ message: "password reset successfully" });
};

exports.logout = async (request, reply) => {
  //JWT are stateless, use strategy like referesh token or blacklist token for more
  return reply.send({ message: "User logged out" });
};
