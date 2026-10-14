import moment from 'moment';

export default function App({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
