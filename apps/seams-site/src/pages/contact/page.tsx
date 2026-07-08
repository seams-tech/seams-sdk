import React from 'react';
import { H2Footer } from '@/components/h2/sections';
import NavbarStatic from '@/components/Navbar/NavbarStatic';
import '@/styles/h2.css';
import './styles.css';

export function ContactPage(): React.JSX.Element {
  return (
    <div className="h2-page h2-page--zoom">
      <NavbarStatic appearance="light" />
      <div className="h2-col">
        <main className="contact-page" aria-labelledby="contact-page-title">
          <section className="contact-page__grid">
            <header className="contact-page__intro">
              <h1 id="contact-page-title">Talk to us.</h1>
              <p>
                Tell us what you&apos;re building. We&apos;ll show you how to bring it onchain with
                secure, compliant wallet infrastructure.
              </p>
            </header>

            <form
              className="contact-form"
              aria-label="Contact sales form"
              onSubmit={(e) => e.preventDefault()}
            >
              <div className="contact-form__row contact-form__row--two">
                <label className="contact-form__field">
                  <span className="contact-form__label">
                    First Name
                    <span className="contact-form__required" aria-hidden>
                      *
                    </span>
                  </span>
                  <input type="text" name="firstName" required />
                </label>
                <label className="contact-form__field">
                  <span className="contact-form__label">
                    Last Name
                    <span className="contact-form__required" aria-hidden>
                      *
                    </span>
                  </span>
                  <input type="text" name="lastName" required />
                </label>
              </div>

              <label className="contact-form__field">
                <span className="contact-form__label">
                  Email
                  <span className="contact-form__required" aria-hidden>
                    *
                  </span>
                </span>
                <input type="email" name="email" required />
              </label>

              <label className="contact-form__field">
                <span className="contact-form__label">
                  Company name
                  <span className="contact-form__required" aria-hidden>
                    *
                  </span>
                </span>
                <input type="text" name="company" required />
              </label>

              <label className="contact-form__field">
                <span className="contact-form__label">
                  Company website (or link to account on X or LinkedIn)
                  <span className="contact-form__required" aria-hidden>
                    *
                  </span>
                </span>
                <input type="url" name="website" required />
              </label>

              <label className="contact-form__field">
                <span className="contact-form__label">
                  What best describes the industry your company is in?
                  <span className="contact-form__required" aria-hidden>
                    *
                  </span>
                </span>
                <span className="contact-form__select-wrap">
                  <select name="industry" required defaultValue="">
                    <option value="" disabled>
                      Select an industry
                    </option>
                    <option value="defi">DeFi</option>
                    <option value="payments">Payments</option>
                    <option value="consumer">Consumer app</option>
                    <option value="enterprise">Enterprise software</option>
                    <option value="other">Other</option>
                  </select>
                </span>
              </label>

              <label className="contact-form__field">
                <span className="contact-form__label">
                  Tell us what you&apos;d like to discuss.
                  <span className="contact-form__required" aria-hidden>
                    *
                  </span>
                </span>
                <textarea
                  name="details"
                  required
                  rows={3}
                  placeholder="Let us know how we can help! The more details you provide, the better we will be able to serve you."
                />
              </label>

              <label className="contact-form__field">
                <span className="contact-form__label">
                  Where did you first hear about Seams?
                  <span className="contact-form__required" aria-hidden>
                    *
                  </span>
                </span>
                <span className="contact-form__select-wrap">
                  <select name="source" required defaultValue="">
                    <option value="" disabled>
                      Select where you heard about Seams
                    </option>
                    <option value="x">X / Twitter</option>
                    <option value="linkedin">LinkedIn</option>
                    <option value="search">Search</option>
                    <option value="friend">Friend or colleague</option>
                    <option value="event">Conference or event</option>
                  </select>
                </span>
              </label>

              <div className="contact-form__captcha" aria-hidden="true">
                <span>protected by reCAPTCHA</span>
                <small>Privacy - Terms</small>
              </div>

              <button type="submit" className="contact-form__submit">
                Submit
              </button>
            </form>
          </section>
        </main>
        <H2Footer />
      </div>
    </div>
  );
}

export default ContactPage;
