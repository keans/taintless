export const View = (props: { on: boolean }) => {
  if (props.on) {
    return <div>on</div>;
  }
  return null;
};
