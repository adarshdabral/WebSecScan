# WebSec Scanner Frontend

A modern React frontend for the WebSec Scanner application that provides a user-friendly interface for performing various security scans on websites.

## Features

- Modern, responsive UI with dark mode support
- Multiple scan types:
  - Basic Website Information
  - SQL Injection Scan
  - Weak Password Check
  - Website Stress Test
  - XSS Vulnerability Check
  - Deface Vulnerability Check
  - DNS Records Check
  - Full Comprehensive Scan
- Real-time scan results with collapsible sections
- Progress indicators and notifications
- Error handling and validation

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Backend server running on port 10037

## Installation

1. Clone the repository
2. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
3. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```

## Development

To start the development server:

```bash
npm start
# or
yarn start
```

The application will be available at `http://localhost:3000`.

## Building for Production

To create a production build:

```bash
npm run build
# or
yarn build
```

The build output will be in the `build` directory.

## Usage

1. Enter the website URL you want to scan
2. Select one or more scan types
3. Click "Start Scan"
4. View the results in the collapsible sections below

## Technologies Used

- React
- TypeScript
- Tailwind CSS
- React Query
- Axios
- React Toastify
- Heroicons

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 