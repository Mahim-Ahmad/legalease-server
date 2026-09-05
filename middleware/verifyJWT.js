import jwt from "jsonwebtoken";

export const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("verifyJWT: no Authorization header on", req.method, req.path);
    return res.status(401).send({ message: "Unauthorized access" });
  }
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log("verifyJWT failed:", err.name, err.message, "on", req.method, req.path);
      return res.status(401).send({ message: "Unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

// Requires a usersCollection to look up the caller's current role
export const verifyRole = (usersCollection, ...allowedRoles) => {
  return async (req, res, next) => {
    const user = await usersCollection.findOne({ email: req.decoded.email });
    if (!user || !allowedRoles.includes(user.role)) {
      return res.status(403).send({ message: "Forbidden access" });
    }
    req.callerRole = user.role;
    next();
  };
};
