import React from 'react';
import { H2Footer } from '@/components/h2/sections';
import NavbarCompact from '@/components/Navbar/NavbarCompact';
import '@/styles/h2.css';
import './styles.css';

const SALES_EMAIL_ADDRESS = 'sales@seams.sh';

function readFormValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function handleContactSubmit(event: React.FormEvent<HTMLFormElement>): void {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);
  const name = readFormValue(formData, 'name');
  const email = readFormValue(formData, 'email');
  const company = readFormValue(formData, 'company');
  const details = readFormValue(formData, 'details');
  const subject = `Sales inquiry from ${name} at ${company}`;
  const body = [`Name: ${name}`, `Work email: ${email}`, `Company: ${company}`, '', details].join(
    '\n',
  );

  window.location.assign(
    `mailto:${SALES_EMAIL_ADDRESS}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`,
  );
}

export function ContactPage(): React.JSX.Element {
  return (
    <div className="h2-page">
      <NavbarCompact appearance="light" />
      <div className="h2-col">
        <main className="contact-page h2-rule" aria-labelledby="contact-page-title">
          <section className="contact-page__panel">
            <header className="contact-page__intro">
              <p className="contact-page__kicker">Contact sales</p>
              <h1 id="contact-page-title">Tell us what you&apos;re building.</h1>
              <p>
                Share a little context and we&apos;ll help you plan secure wallets, agent access,
                and policy controls for your product.
              </p>
            </header>

            <form
              className="contact-form"
              aria-label="Contact sales form"
              onSubmit={handleContactSubmit}
            >
              <div className="contact-form__row contact-form__row--two">
                <label className="contact-form__field">
                  <span className="contact-form__label">Name</span>
                  <input type="text" name="name" autoComplete="name" required />
                </label>
                <label className="contact-form__field">
                  <span className="contact-form__label">Work email</span>
                  <input type="email" name="email" autoComplete="email" required />
                </label>
              </div>

              <label className="contact-form__field">
                <span className="contact-form__label">Company</span>
                <input type="text" name="company" autoComplete="organization" required />
              </label>

              <label className="contact-form__field">
                <span className="contact-form__label">Project details</span>
                <textarea
                  name="details"
                  required
                  rows={5}
                  placeholder="What are you building, and where can Seams help?"
                />
              </label>

              <div className="contact-form__actions">
                <button type="submit" className="contact-form__submit">
                  Email sales
                </button>
                <span>Opens your default email app</span>
              </div>
            </form>
          </section>
        </main>
        <H2Footer />
      </div>
    </div>
  );
}

export default ContactPage;
