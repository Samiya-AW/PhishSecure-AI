import Head from 'next/head';
import FileUpload from '/components/FileUpload';

export default function Home() {
  return (
    <div className="container">
      <Head>
        <title>Phish Analyzer</title>
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main>
        <h1 className="title">Phish Analyzer</h1>
        <FileUpload />
      </main>

      <style jsx>{`
        .container {
          min-height: 100vh;
          padding: 0 0.5rem;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          background-color: #121212;
          color: #ffffff;
        }
        .title {
          margin: 0 0 2rem;
          font-size: 4rem;
        }
      `}</style>
    </div>
  );
}