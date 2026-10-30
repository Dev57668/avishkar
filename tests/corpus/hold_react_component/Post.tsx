import React from 'react';

export function Post({ html, title }: { html: string; title: string }) {
  return (
    <article>
      <h1>{title}</h1>
      <div dangerouslySetInnerHTML={{ __html: html }} />
    </article>
  );
}
