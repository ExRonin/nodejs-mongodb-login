const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;


var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
var salt = bcrypt.genSaltSync(10);
exports.signup = (req, res) => {
  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8),
  });

  user.save((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    if (req.body.roles) {
      Role.find(
        {
          name: { $in: req.body.roles },
        },
        (err, roles) => {
          if (err) {
            res.status(500).send({ message: err });
            return;
          }

          user.roles = roles.map((role) => role._id);
          user.save((err) => {
            if (err) {
              res.status(500).send({ message: err });
              return;
            }

            res.send({ message: "User was registered successfully!" });
          });
        }
      );
    } else {
      Role.findOne({ name: "user" }, (err, role) => {
        if (err) {
          res.status(500).send({ message: err });
          return;
        }

        user.roles = [role._id];
        user.save((err) => {
          if (err) {
            res.status(500).send({ message: err });
            return;
          }

          res.send({ message: "User was registered successfully!" });
        });
      });
    }
  });
};

exports.signin = (req, res) => {
  User.findOne({
    username: req.body.username,
  })
    .populate("roles", "-__v")
    .exec((err, user) => {
      if (err) {
        res.status(500).send({ message: err });
        return;
      }

      if (!user) {
        return res.status(404).send({ message: "User Not found." });
      }

      var passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );

      if (!passwordIsValid) {
        return res.status(401).send({ message: "Invalid Password!" });
      }

      var token = jwt.sign({ id: user.id }, config.secret, {
        expiresIn: 86400, // 24 hours
      });

      var authorities = [];

      for (let i = 0; i < user.roles.length; i++) {
        authorities.push("ROLE_" + user.roles[i].name.toUpperCase());
      }

      req.session.token = token;

      res.status(200).send({
        id: user._id,
        username: user.username,
        email: user.email,
        roles: authorities,
      });
    });
};

exports.signout = async (req, res) => {
  try {
    req.session = null;
    return res.status(200).send({ message: "You've been signed out!" });
  } catch (err) {
    this.next(err);
  }
};


//editan lupa password
exports.requestPasswordReset = (req, res, next) => {
  const async = require('async');
  const crypto = require('node:crypto');
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({email: req.body.email }, function(err, user) {
        if (!user) {
        console.log('error', 'No account with that email address exists.');
       // req.flash('error', 'No account with that email address exists.');
       return res.status(404).send({ message: "Email Not found." });
        }
console.log('step 1')
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
        console.log('step 2')


      var smtpTrans = nodemailer.createTransport({
         service: 'Gmail', 
         auth: {
          user: 'myemail',
          pass: 'mypassword'
        }
      });
      var mailOptions = {

        to: user.email,
        from: 'myemail',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.Host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'

      };
      console.log('step 3')

        smtpTrans.sendMail(mailOptions, function(err) {
        req.flash('success', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        console.log('sent')
        res.redirect('/forgot');
});
}
  ], function(err) {
    console.log('this err' + ' ' + err)
    res.redirect('/');
  });
};






// exports.requestPasswordReset = async (req,res) => {
//   const user = await User.findOne({ email: req.body.email}).exec();
//   if (user) return res.status(404).send({ message: "Email Not found." });
//   let token = await User.findOne({  username: req.body.username, });
//   if (token) await token.deleteOne();

//   let resetToken = crypto.randomBytes(32).toString("hex");
//   const hash = await bcrypt.hash(resetToken, Number(bcryptSalt));

//   await new Token({
//     id: user._id,
//     token: hash,
//     createdAt: Date.now(),
//   }).save();

//   const link = `${clientURL}/passwordReset?token=${resetToken}&id=${user._id}`;

//   sendEmail(
//     user.email,
//     "Password Reset Request",
//     {
//       name: user.name,
//       link: link,
//     },
//     "./template/requestResetPassword.handlebars"
//   );
//   return link;
// };

// exports.resetPassword = async (userId, token, password) => {
//   let passwordResetToken = await token.findOne({ userId });

//   if (!passwordResetToken) {
//     throw new Error("Invalid or expired password reset token");
//   }

//   const isValid = await bcrypt.compare(token, passwordResetToken.token);

//   if (!isValid) {
//     throw new Error("Invalid or expired password reset token");
//   }

//   const hash = await bcrypt.hash(password, Number(bcryptSalt));

//   await User.updateOne(
//     { _id: userId },
//     { $set: { password: hash } },
//     { new: true }
//   );

//   const user = await User.findById({ _id: userId });

//   sendEmail(
//     user.email,
//     "Password Reset Successfully",
//     {
//       name: user.name,
//     },
//     "./template/resetPassword.handlebars"
//   );

//   await passwordResetToken.deleteOne();

//   return true;
// };

// exports.resetPasswordRequestController = async (req, res, next) => {
//   const requestPasswordReset = await requestPasswordReset(
//     req.body.email
//   );
//   return res.json(requestPasswordReset);
// };

// exports.resetPasswordController = async (req, res, next) => {
//   const resetPassword = await resetPassword(
//     req.body.user,
//     req.body.token,
//     req.body.password
//   );
//   return res.json(resetPassword);
// };