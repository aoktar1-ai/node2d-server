# Node2D Editor Cloud Server

Multi-user project server for Node2D Editor with real-time collaboration, project sharing, and version history.

## Features

- **User Authentication**: Register, login, JWT-based authentication
- **Project Management**: Create, edit, delete, fork projects
- **Collaboration**: Share projects with specific users (view/edit/admin permissions)
- **Public Gallery**: Explore public projects, search by tags
- **Version History**: Automatic versioning with restore capability
- **Social Features**: Stars, follows, user profiles
- **File Assets**: Upload images and other assets per project

## Quick Start with Dokploy

### 1. Create PostgreSQL Database

In Dokploy, create a PostgreSQL database:
- Name: `node2d-db`
- Database: `node2d`
- Username: `node2d`
- Password: (generate secure password)

### 2. Deploy the Application

1. Create a new application in Dokploy
2. Connect your Git repository or upload the code
3. Set environment variables:

```env
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://node2d:YOUR_PASSWORD@node2d-db:5432/node2d
JWT_SECRET=your-super-secret-key-at-least-32-characters-long
CORS_ORIGIN=https://your-editor-domain.com
```

4. Deploy!

### 3. Configure Domain

Set up your domain (e.g., `api.yourdomain.com`) pointing to the application.

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login |
| GET | `/api/auth/me` | Get current user |
| PUT | `/api/auth/profile` | Update profile |

### Projects

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects` | Get user's projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/:id` | Get project by ID |
| PUT | `/api/projects/:id` | Update project |
| DELETE | `/api/projects/:id` | Delete project |
| POST | `/api/projects/:id/fork` | Fork project |
| GET | `/api/projects/explore` | Browse public projects |
| GET | `/api/projects/shared` | Get projects shared with user |

### Collaboration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects/:id/collaborators` | List collaborators |
| POST | `/api/projects/:id/collaborators` | Add collaborator |
| DELETE | `/api/projects/:id/collaborators/:userId` | Remove collaborator |

### Stars

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/projects/:id/star` | Star project |
| DELETE | `/api/projects/:id/star` | Unstar project |

### Versions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects/:id/versions` | Get version history |
| POST | `/api/projects/:id/versions/:versionId/restore` | Restore version |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users/:username` | Get user profile |
| GET | `/api/users/:username/projects` | Get user's public projects |
| GET | `/api/users/:username/starred` | Get user's starred projects |
| POST | `/api/users/:username/follow` | Follow user |
| DELETE | `/api/users/:username/follow` | Unfollow user |

## C++ Client Integration

### Setup

1. Copy `CloudClient.h` and `CloudClient.cpp` to your Node2D Editor project
2. Add nlohmann/json dependency
3. For WebAssembly: Link with `-s FETCH=1`
4. For Desktop: Link with libcurl

### Usage Example

```cpp
#include "CloudClient.h"

using namespace Node2DCloud;

void initCloud() {
    auto& client = GetCloudClient();
    client.setBaseUrl("https://api.yourdomain.com");
    
    // Check if already logged in
    if (client.isLoggedIn()) {
        client.fetchCurrentUser([](const User& user, const auto& error) {
            if (!error) {
                std::cout << "Welcome back, " << user.displayName << "!\n";
            }
        });
    }
}

void login(const std::string& username, const std::string& password) {
    auto& client = GetCloudClient();
    
    client.login(username, password, [](const User& user, const auto& error) {
        if (error) {
            std::cerr << "Login failed: " << error->message << "\n";
            return;
        }
        std::cout << "Logged in as " << user.username << "\n";
    });
}

void saveProject(int projectId, const json& sceneData) {
    auto& client = GetCloudClient();
    
    client.saveProjectData(projectId, sceneData, "Auto-save",
        [](const Project& project, const auto& error) {
            if (error) {
                std::cerr << "Save failed: " << error->message << "\n";
                return;
            }
            std::cout << "Saved! Version: " << project.version << "\n";
        });
}

void createNewProject(const std::string& name, const json& initialData) {
    auto& client = GetCloudClient();
    
    client.createProject(name, "My new project", initialData, "private", {"game", "2d"},
        [](const Project& project, const auto& error) {
            if (error) {
                std::cerr << "Create failed: " << error->message << "\n";
                return;
            }
            std::cout << "Created project ID: " << project.id << "\n";
        });
}

void loadProject(int projectId) {
    auto& client = GetCloudClient();
    
    client.getProject(projectId, [](const Project& project, const auto& error) {
        if (error) {
            std::cerr << "Load failed: " << error->message << "\n";
            return;
        }
        
        // project.projectData contains your scene JSON
        auto& sceneData = project.projectData;
        // Load into editor...
    });
}

void shareProject(int projectId, const std::string& username) {
    auto& client = GetCloudClient();
    
    client.addCollaborator(projectId, username, "edit", [](const auto& error) {
        if (error) {
            std::cerr << "Share failed: " << error->message << "\n";
            return;
        }
        std::cout << "Project shared!\n";
    });
}
```

## Database Schema

The server automatically creates the following tables:

- `users` - User accounts
- `projects` - Project metadata and data (JSONB)
- `project_collaborators` - Sharing permissions
- `project_stars` - Project likes
- `project_comments` - Comments on projects
- `project_versions` - Version history
- `assets` - Uploaded files
- `user_follows` - Social follows
- `activity_log` - User activity tracking

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | Secret for JWT tokens | Required |
| `CORS_ORIGIN` | Allowed origins | * |
| `UPLOAD_DIR` | Directory for file uploads | ./uploads |
| `NODE_ENV` | Environment | development |

## Security Considerations

1. Always use HTTPS in production
2. Set a strong `JWT_SECRET` (32+ characters)
3. Configure `CORS_ORIGIN` to only allow your editor domain
4. Use environment variables for sensitive data
5. Enable rate limiting (already configured)

## Local Development

```bash
# Clone the repository
git clone <your-repo>
cd node2d-server

# Install dependencies
npm install

# Start with Docker Compose (includes PostgreSQL)
docker-compose up -d

# Or run directly (requires external PostgreSQL)
export DATABASE_URL="postgresql://user:pass@localhost:5432/node2d"
npm run dev
```

## License

MIT
