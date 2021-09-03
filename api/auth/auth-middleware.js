const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const User = require("../users/users-model.js");

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({ message: "Token required" });
    } else {
      jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
        if (err) {
          return res.status(401).json({ message: "Token invalid" });
        } else {
          req.decodedToken = decodedToken;
          next();
        }
      });
    }
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    const decodedToken = req.decodedToken;
    if (decodedToken.role_name !== role_name) {
      return res.status(403).json({ message: "This is not for you" });
    } else {
      next();
    }
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */

  // return res.json({ message: `username: ${req.body.username}, password ${req.body.password}` });
  const rows = User.findBy({ username: req.body.username });
  if (rows.length) {
    req.userData = rows[0];
    next();
  } else {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // User.findBy({ username: req.body.username })
  //   .then(user => {
  //     if (!user) {
  //       return res.status(401).json({ message: "Invalid credentials" });
  //     } else {
  //       next();
  //     } 
  //   })

  // try {
  //   const rows = await User.findBy({username: req.body.username});
  //   if (rows.lenth) {
  //     req.userData = rows[0];
  //     next();
  //   } else {
  //     return res.status(401).json({ message: "Invalid credentials" });
  //   }
  // } catch (error) {
  //   next(error);
  // }
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
 if (req.body.role_name) {
    req.role_name = req.body.role_name.trim();
    if (req.role_name === '') {
      req.role_name = 'student';
    } else if (req.role_name === 'admin') {
      return res.status(422).json({ message: "Role name can not be admin" });
    } else if (req.role_name.length > 32) {
      return res.status(422).json({ message: "Role name can not be longer than 32 chars" });
    }
  } else {
    req.role_name = 'student';
  }
  next();
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
