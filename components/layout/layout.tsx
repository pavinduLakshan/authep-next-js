import React from "react";
import { Header } from "./header";
import { Footer } from "./footer";

const Layout = ({ children }: { children: React.ReactElement }) => {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        flexDirection: "column",
        alignItems: "center",
        minHeight: '100vh'
      }}
    >
      <Header />
      {children}
      <Footer />
    </div>
  );
};

export { Layout };
