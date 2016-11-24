import Vapor
import Auth
import Fluent
import HTTP
import VaporMemory

let drop = Droplet()

try drop.addProvider(VaporMemory.Provider.self) // in memory "database"
let auth = AuthMiddleware(user: User.self)
drop.middleware.append(auth)
drop.preparations = [User.self]

drop.get("") { request in
    if let u = request.user() {
        return try drop.view.make("currentUser", ["name": u.name, "id": "\(u.id?.int)"])
    }
    return try drop.view.make("login")
}

drop.get("register") { request in
    if let u = request.user() {
        return Response(redirect: "/")
    }
    return try drop.view.make("register")
}

drop.group("users") { users in
    users.get(handler: { request in
        if let u = request.user() {
            return try drop.view.make("currentUser", ["name": u.name, "id": "\(u.id?.int)"])
        }
        return Response(redirect: "/")
    })

    users.post { req in
        guard let name = req.data["name"]?.string else {
            throw Abort.badRequest
        }

        var user = User(name: name)
        try user.save()

        guard let id = user.id else {
            throw Abort.serverError
        }
        let creds = Identifier(id: id)
        try req.auth.login(creds)

        if req.accept.prefers("html") {
            return try drop.view.make("currentUser", ["name": user.name, "id": "\(user.id?.int)"])
        }
        // default to json
        return user
    }

    users.post("login") { req in
        guard let id = req.data["id"]?.string else {
            throw Abort.badRequest
        }

        let creds = try Identifier(id: id)
        try req.auth.login(creds)

        if req.accept.prefers("html") {
            return try drop.view.make("currentUser")
        }

        return try JSON(node: ["message": "Logged in via default, check vapor-auth cookie."])
    }

    users.post("logout") { req in
        try req.auth.logout()
        return Response(redirect: "/")
    }

    let protect = ProtectMiddleware(error:
        Abort.custom(status: .forbidden, message: "Not authorized.")
    )
    users.group(protect) { secure in
        secure.get("secure") { req in
            if let u = req.user() {
                return u
            }
            return ""
        }
    }
}

drop.run()
