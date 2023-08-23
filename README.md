## Authentication Portal in Next.js

This project is to rewrite the JSP based authentication portal functionality in WSO2 Identity Server using [Next.js](https://nextjs.org/).

This effort was inspired by [this StackOverflow article](https://stackoverflow.com/collectives/wso2/articles/74092534/hosting-authentication-portal-in-docker-for-wso2-is-6-0-0) by [@VivekVinushanth](https://github.com/VivekVinushanth)

## Getting Started

1. Clone the repository.

```bash
git clone 
```

2. Install the dependencies.

```bash
npm install
# or
yarn
```

3. Start the development server:

```bash
npm run dev
# or
yarn dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.


[API routes](https://nextjs.org/docs/api-routes/introduction) can be accessed on [http://localhost:3000/api/hello](http://localhost:3000/api/hello). This endpoint can be edited in `pages/api/hello.ts`.

The `pages/api` directory is mapped to `/api/*`. Files in this directory are treated as [API routes](https://nextjs.org/docs/api-routes/introduction) instead of React pages.
