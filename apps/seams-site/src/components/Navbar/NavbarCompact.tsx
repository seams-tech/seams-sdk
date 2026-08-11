import React from 'react';
import { NavbarStatic, type NavbarStaticProps } from './NavbarStatic';

export type NavbarCompactProps = Omit<NavbarStaticProps, 'layout'>;

export function NavbarCompact(props: NavbarCompactProps): React.JSX.Element {
  return <NavbarStatic {...props} layout="compact" />;
}

export default NavbarCompact;
