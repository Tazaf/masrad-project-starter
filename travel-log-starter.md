# MAS-RAD | CAS-DAR | DFA - Travel Log Project Starter

<a name="top"></a>

This repository contains instructions to build a skeleton application that can serve as a starting point to develop the Travel Log web application.

This material is part of the [Advanced Front-end Development](https://github.com/MediaComem/comem-masrad-dfa) for the [Master of Advances Studies in Rapid Application Development](https://www.he-arc.ch/ingenierie/mas-rad-cas-dar).

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Prerequisites](#prerequisites)
- [Features](#features)
- [Design the user interface](#design-the-user-interface)
- [Set up the application](#set-up-the-application)
  - [Create a blank Angular app](#create-a-blank-angular-app)
  - [Serve the application locally](#serve-the-application-locally)
- [Set up security](#set-up-security)
  - [Check the documentation of the API's authentication resource](#check-the-documentation-of-the-apis-authentication-resource)
  - [Create model classes](#create-model-classes)
  - [Create a security feature module](#create-a-security-feature-module)
  - [Create an authentication service](#create-an-authentication-service)
  - [Create the login screen](#create-the-login-screen)
  - [Use the authentication service to protect access to restricted pages](#use-the-authentication-service-to-protect-access-to-restricted-pages)
  - [Storing the authentication credentials](#storing-the-authentication-credentials)
  - [Logout button](#logout-button)
  - [Configuring an HTTP interceptor](#configuring-an-http-interceptor)
- [Multi-environment & sensitive configuration](#multi-environment--sensitive-configuration)
  - [Environment files](#environment-files)
  - [Create the actual configuration file](#create-the-actual-configuration-file)
  - [Add the environment files to your `.gitignore` file](#add-the-environment-files-to-your-gitignore-file)
  - [When are the environment files used](#when-are-the-environment-files-used)
  - [Feed the configuration to Angular](#feed-the-configuration-to-angular)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Prerequisites

These instructions assume that you are using the Travel Log API and have read its [documentation](https://comem-travel-log-api.herokuapp.com/).

You will need to have [Node.js](https://nodejs.org) installed.
The latest LTS (Long Term Support) version is recommended (v12.18.0 at the time of writing these instructions).

<a href="#top">↑ Back to top</a>

## Features

The features that the final application should support can be found in [the course introduction subject](https://mediacomem.github.io/comem-masrad-dfa/latest/subjects/intro/#12).

This starter instructions will ONLY cover **registering and logging users**. The rest is up to you.

<a href="#top">↑ Back to top</a>

## Design the user interface

Before diving into the code, you should always take a moment to design the user interface of your app.
This doesn't have to be a final design, but it should at least be a sketch of what you want.

This helps you think in terms of the whole app and of the relationships between screens.

**DO NOT underestimate the importance of this step.**

You're strongly advised to take some time and think about all the features, how they interact with each other, and how you will present those features to your users in a meaningful and streamlined way.

> We sadly do not have the time to dive into the area of UX and UI concepts, but you definitely should do some research about the basic principles

<a href="#top">↑ Back to top</a>

## Set up the application

### Create a blank Angular app

Make sure you have [Angular CLI][ng-cli] installed:

```bash
$> ng v
Angular CLI: 9.1.7
```

> If you have an error when running the above command, this probably means that you need to install [Angular CLI][ng-cli]. To do so, execute:
>
> ```bash
> $> npm install -g @angular/cli@latest
> ```

Go in the directory where you want the app source code to be located, then generate a blank Angular app with the following command:

> No need to create a dedicated directory for your app ; it will be created for you by the CLI tool

```bash
$> cd /path/to/projects
$> ng new travel-log --routing=true
```

> When asked, select the CSS processor of your choice

Then wait for the install to proceed... ⏳

Go into the app directory. The `ng new` command should have already initialized a Git repository and made the first commit:

```bash
$> cd travel-log
$> git log
commit 2a3f83f14ae2a82d00cb2b2960dda1c1e0b0a432 (HEAD -> master)
Author: John Doe <john.doe@example.com>
Date:   Thu Jun 11 12:54:34 2020 +0200

    initial commit
```

<a href="#top">↑ Back to top</a>

### Serve the application locally

To make sure everything was set up correctly, use the following command from the root of your project directory to serve the application locally in your browser:

```bash
$> npm start
```

Open your Browser and go to [`http://localhost:4200`](http://localhost:4200). You should see the Angular landing page:

![Serving the blank app](images/blank-app-serve.png)

<a href="#top">↑ Back to top</a>

## Set up security

To use the app, a user should identify themselves.
We will add a login screen that the user must go through before accessing the other screens.
Authentication will be performed by the [Travel Log API][travel-log-api].

The API requires a `Bearer` token be sent to identify the user when making requests on some resources (e.g. when creating trips).
This token must be sent in the `Authorization` header for all requests requiring identification.
Once login/logout is implemented, we will also set up an HTTP interceptor to automatically add this header to every request.

### Check the documentation of the API's authentication resource

The Travel Log API provides an [`/auth` resource](https://comem-travel-log-api.herokuapp.com/#api-Authentication-CreateAuthenticationToken)
on which you can make a `POST` request to authenticate a user.

You need to make a call that looks like this:

```json
POST /api/auth HTTP/1.1
Content-Type: application/json

{
  "username": "jdoe",
  "password": "test"
}
```

The response will contain the token we need for authentication,
as well as a representation of the authenticated user:

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token": "eyJhbGciOiJIU.eyJpc3MiOiI1OGM1YjUwZTA0Nm.gik21xyT4_NzsduWMLVp8",
  "user": {
    "createdAt": "2018-12-09T11:58:18.265Z",
    "href": "/api/users/d68cf4e9-1349-4d45-b356-c1294e49ef23",
    "id": "d68cf4e9-1349-4d45-b356-c1294e49ef23",
    "name": "jdoe",
    "tripsCount": 2,
    "updatedAt": "2018-12-09T11:58:18.265Z"
  }
}
```

You will need to perform this request and retrieve that information when the user logs in.

<a href="#top">↑ Back to top</a>

### Create model classes

Let's create a few classes to use as models when communicating with the API.
That way we will benefit from TypeScript's typing when accessing model properties.

Create a `src/app/models/user.ts` file which exports a model representing a user of the API:

```ts
export class User {
  id: string;
  href: string;
  name: string;
  tripsCount: number;
  createdAt: string;
  updatedAt: string;
}
```

Create a `src/app/models/auth-request.ts` file which exports a model representing a request to the authentication resource:

```ts
export class AuthRequest {
  username: string;
  password: string;
}
```

Create a `src/app/models/auth-response.ts` file which exports a model representing a successful response from the authentication resource:

```ts
import { User } from "./user";

export class AuthResponse {
  token: string;
  user: User;
}
```

### Create a security feature module

We will define several features and utils related to managing security in our app.

Let's group them in a dedicated feature module:

```bash
$> ng generate module Security
```

> This module does not need `--routing` since it will only provide feature and not directly add new navigation in the final app

### Create an authentication service

Since the new service we'll create will make Http requests, we need to import Angular's `HttpClientModule` in our app. Do so in the `src/app/app.module.ts` file:

```ts
// ...Other imports
// TODO: import Angular's httpClientModule
import { HttpClientModule } from "@angular/common/http";

@NgModule({
  declarations: [AppComponent],
  imports: [
    /* ... */
    HttpClientModule, // TODO: add Angular's HttpClientModule to your module imports
  ],
  providers: [],
  bootstrap: [AppComponent],
})
export class AppModule {}
```

Now, let's generate a reusable, injectable service to manage authentication in our `security` directory:

```bash
$> ng generate service security/Auth
```

You can replace the content of the generated `src/app/security/auth.service.ts` file with the following code:

```ts
import { Injectable } from "@angular/core";
import { Observable, ReplaySubject } from "rxjs";
import { AuthResponse } from "../models/auth-response";
import { HttpClient } from "@angular/common/http";
import { map } from "rxjs/operators";
import { User } from "../models/user";
import { AuthRequest } from "../models/auth-request";

// TODO: Insert here your personnal api URL
const apiUrl = "<REPLACE_ME>";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  /**
   * A "ReplaySubject" is a Subject (a source of an Observable) that emits a predefined number of previously emitted
   * values to an Observer when it subscribes to it.
   * It will act as a sort of local "cache" for the AuthResponse object value.
   */
  private authenticated$: ReplaySubject<AuthResponse>;

  constructor(private http: HttpClient) {
    // Create the ReplaySubject and configure it so that it emits the latest emitted value on each subscription
    this.authenticated$ = new ReplaySubject(1);
    // Emit a null value as the initial value
    this.authenticated$.next(null);
  }

  /**
   * Checks if the user is authenticated by casting the latest AuthResponse value as a boolean
   */
  isAuthenticated(): Observable<boolean> {
    return this.authenticated$.pipe(map((auth) => Boolean(auth)));
  }

  /**
   * Retrieves the User object from the latest AuthResponse value
   */
  getUser(): Observable<User> {
    return this.authenticated$.pipe(
      map((auth) => (auth ? auth.user : undefined))
    );
  }

  /**
   * Retrieves the token string from the latest AuthResponse value
   */
  getToken(): Observable<string> {
    return this.authenticated$.pipe(
      map((auth) => (auth ? auth.token : undefined))
    );
  }

  /**
   * Logs in a user with the provided AuthRequest object and emits the received AuthResponse if successful.
   */
  login(authRequest: AuthRequest): Observable<User> {
    return this.http.post<AuthResponse>(`${apiUrl}/auth`, authRequest).pipe(
      map((response) => {
        this.authenticated$.next(response);
        console.log(`User ${response.user.name} logged in`);
        return response.user;
      })
    );
  }

  /**
   * Logs out a user and emit an empty AuthResponse
   */
  logout() {
    this.authenticated$.next(null);
    console.log("User logged out");
  }
}
```

### Create the login screen

Generate a login page component declared by the `SecurityModule`:

```bash
$> ng generate component security/LoginPage
```

Since this login screen will be composed of a form, you'll need to import the `FormsModule` in your `SecurityModule`.

While you're at ti, add the `LoginPageComponent` to the `exports` array of the `SecurityModule` configuration in `security.module.ts`, to make it visible when importing the `SecurityModule` into the `AppModule` :

```ts
// Imports
import { FormsModule } from "@angular/forms";

@NgModule({
  // ...
  imports: [CommonModule, FormsModule],
  // ...
  exports: [LoginPageComponent],
})
export class SecurityModule {}
```

Update the generated `src/app/security/login-page/login-page.component.ts` as follows:

```ts
import { Component, OnInit } from "@angular/core";
import { AuthRequest } from "src/app/models/auth-request";
import { AuthService } from "../auth.service";
import { Router } from "@angular/router";
import { NgForm } from "@angular/forms";

@Component({
  selector: "app-login-page",
  templateUrl: "./login-page.component.html",
  styleUrls: ["./login-page.component.scss"],
})
export class LoginPageComponent {
  /**
   * This authentication request object will be updated when the user
   * edits the login form. It will then be sent to the API.
   */
  authRequest: AuthRequest;

  /**
   * If true, it means that the authentication API has return a failed response
   * (probably because the name or password is incorrect).
   */
  loginError: boolean;

  constructor(private auth: AuthService, private router: Router) {
    this.authRequest = new AuthRequest();
    this.loginError = false;
  }

  /**
   * Called when the login form is submitted.
   */
  onSubmit(form: NgForm) {
    // Only do something if the form is valid
    if (form.valid) {
      // Hide any previous login error.
      this.loginError = false;

      // Perform the authentication request to the API.
      this.auth.login(this.authRequest).subscribe({
        next: () => this.router.navigateByUrl("/"),
        error: (err) => {
          this.loginError = true;
          console.warn(`Authentication failed: ${err.message}`);
        },
      });
    }
  }
}
```

Replace the content of the generated `src/app/security/login-page/login-page.component.html` file with:

```html
<form #loginForm="ngForm" (submit)="onSubmit(loginForm)">
  <div>
    <label for="username">Username</label>
    <input
      type="text"
      name="username"
      id="username"
      #usernameField="ngModel"
      required
      [(ngModel)]="authRequest.username"
    />
    <p *ngIf="usernameField.hasError('required') && usernameField.touched">
      Username is required
    </p>
  </div>
  <div>
    <label for="password">Password</label>
    <input
      type="password"
      name="password"
      id="passwrod"
      #passwordField="ngModel"
      required
      [(ngModel)]="authRequest.password"
    />
    <p *ngIf="passwordField.hasError('required') && passwordField.touched">
      Password is required
    </p>
  </div>

  <div>
    <button type="submit" [disabled]="loginForm.invalid">Log in</button>
    <p *ngIf="loginError">
      Unable to log in. See the log for more information.
    </p>
  </div>
</form>
```

Adds a route displaying this component in `app-routing.module.ts`:

```ts
const routes: Routes = [{ path: "login", component: LoginPageComponent }];
```

<a href="#top">↑ Back to top</a>

### Use the authentication service to protect access to restricted pages

Now that we have a service to manage authentication and a working page for users to log in, we need to make sure that unauthenticated user can not access restricted pages and are instead redirected to the login page.

We will use an [Angular Guard][angular-guard] to do this.

```bash
$> ng generate guard security/guards/Auth
```

> When asked what interface you'd like to implement, select only the `CanActivate` interface.

Open the `src/app/security/guards/auth.guard.ts` file and **replace all its content** with:

```ts
import { Injectable } from "@angular/core";
import {
  ActivatedRouteSnapshot,
  CanActivate,
  Router,
  RouterStateSnapshot,
  UrlTree,
} from "@angular/router";
import { Observable } from "rxjs";
import { map } from "rxjs/operators";
import { AuthService } from "../auth.service";

@Injectable({
  providedIn: "root",
})
export class AuthGuard implements CanActivate {
  constructor(private auth: AuthService, private router: Router) {}

  canActivate(
    next: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean | UrlTree> {
    return (
      this.auth
        // Use this to check if the user is authenticated
        .isAuthenticated()
        // If they're authenticated, return true, otherwise, returns an UrlTree to redirect to the login page
        .pipe(map((auth) => (auth ? true : this.router.parseUrl("/login"))))
    );
  }
}
```

To test this guard, let's create a dummy page that we'll use as the default page of our app:

```bash
$> ng generate component DummyPage
```

> You'll be able to delete this page once you have created your real default page

Then open the `src/app/app-routing.module.ts` file and add a new route for this page:

```ts
const routes: Routes = [
  // Add this default route to redirect to dummy
  { path: "", redirectTo: "dummy", pathMatch: "full" },
  { path: "login", component: LoginPageComponent },
  // Add the route to display the dummy page
  {
    path: "dummy",
    component: DummyPageComponent,
    // Prevent access to this page to unauthenticated users
    canActivate: [AuthGuard],
  },
];
```

The login screen is ready!
If you reload your app, you should see that you are automatically redirected to the login page.

You should be able to log in using your firstname as username (all lowercase and without any space or dash) and the password `1234`.

<a href="#top">↑ Back to top</a>

### Storing the authentication credentials

Now you can log in, but there's a little problem.

Every time the app is reloaded, you lose all data so you have to log back in.
This is particularly annoying for local development since the browser is automatically refreshed every time you change the code.

You need to use more persistent storage for the security credentials, i.e. the authentication token.

We will use the `LocalStorage` feature of HTML5 to do so.

Update the `src/app/security/auth.service.ts` file to add the necessary `localStorage` calls:

```ts
// Imports

const apiUrl = "https://masrad-2020-tl-mathias.herokuapp.com/api";

// Add a constant for the storage key
const STORAGE_KEY = "auth";

@Injectable({
  /* ... */
})
export class AuthService {
  constructor(private http: HttpClient) {
    // Get the credentials from the localStorage when the AuthService is created
    // It will either contains an AuthResponse object of null if it does not exist
    const savedAuth = JSON.parse(
      localStorage.getItem(STORAGE_KEY)
    ) as AuthResponse;
    this.authenticated$ = new ReplaySubject(1);
    // Emit the savedAuth as the initial value for the ReplaySubject
    this.authenticated$.next(savedAuth);
  }

  // ...

  login(authRequest: AuthRequest): Observable<User> {
    return this.http.post<AuthResponse>(`${apiUrl}/auth`, authRequest).pipe(
      // The tap operator allows you to do something with an observable's emitted value
      // and emit it again unaltered.
      // In our case, we just store this AuthResponse in the localStorage
      tap((response) => this.saveAuth(response)),
      map((response) => {
        // ...
      })
    );
  }

  logout() {
    // Remove the AuthResponse from the localStorage when user logs out
    localStorage.removeItem(STORAGE_KEY);
    // ...
  }

  /**
   * Saves the AuthResponse in the localStorage
   */
  private saveAuth(auth: AuthResponse) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
  }
}
```

Your app should now remember user credentials even when you reload it!

<a href="#top">↑ Back to top</a>

### Logout button

You should also add a UI component to allow the user to log out.

Let's create a dedicated component for that in our `SecurityModule`:

```bash
$> ng generate component security/LogoutButton
```

Like the `LoginPageComponent`, configure the `SecurityModule` to export this `LogoutButtonComponent`, so the `AppModule` can see it. Do this in `security.module.ts`:

```ts
// Imports

@NgModule({
  // ...
  exports: [LoginPageComponent, LogoutButtonComponent],
})
export class SecurityModule {}
```

Delete the `logout-button.component.html` and `logout-button.component.scss` file as we won't need them, then update the `logout-button.component.ts` file with the following content:

```ts
import { Component, OnInit } from "@angular/core";
import { AuthService } from "../auth.service";
import { Router } from "@angular/router";

@Component({
  selector: "app-logout-button",
  template: '<button (click)="logout()">Logout</button>',
})
export class LogoutButtonComponent {
  constructor(private auth: AuthService, private router: Router) {}

  logout(): void {
    this.auth.logout();
    this.router.navigateByUrl("/login");
  }
}
```

Add this component in the template of our `DummyPage` by adding this line at the end of the `dummy-page.component.html` file:

```html
<app-logout-button></app-logout-button>
```

You should now see the logout button in the navigation bar after logging in and should be able to log out of the application.

<a href="#top">↑ Back to top</a>

### Configuring an HTTP interceptor

Now that you have login and logout functionality, and an authentication service that stores an authentication token, you can authenticate for other API calls.

Looking at the API documentation, you'll see that many operations requires you to send a bearer token in the `Authorization` header, like this:

```
POST /api/trips HTTP/1.1
Authorization: Bearer 0a98wumv
Content-Type: application/json

{"some":"json"}
```

With Angular, you would make a call like this:

```js
httpClient.post("http://example.com/path", body, {
  headers: {
    Authorization: `Bearer ${token}`,
  },
});
```

But it's a bit annoying to have to manually specify this header for every request.
After all, we know that we need it for most calls.

[Interceptors](https://medium.com/@ryanchenkie_40935/angular-authentication-using-the-http-client-and-http-interceptors-2f9d1540eb8)
are Angular services that can be registered with the HTTP client to automatically react to requests (or responses).
This solves our problem: we want to register an interceptor that will automatically add the `Authorization` header to all requests if the user is logged in.

Let's create a service that will be responsible of calling the Travel Log API to list all users.

> You should create a service for each of the resources that the API allows you to manage, and refrains from doing any HTTP calls from your components.

```bash
$> ng generate service api/services/User
```

Replace the content of the generated `src/app/api/services/user.service.ts` file with:

```ts
import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { Observable } from "rxjs";
import { User } from "src/app/models/user";

// TODO: Insert here your personnal api URL
const apiUrl = "<REPLACE_ME>";

@Injectable({
  providedIn: "root",
})
export class UserService {
  constructor(private http: HttpClient) {}

  loadAllUsers(): Observable<User[]> {
    return this.http.get<User[]>(`${apiUrl}/users`);
  }
}
```

Now, update the `DummyPageComponent` to add the following code:

```ts
import { Component, OnInit } from "@angular/core";
import { UserService } from "../api/services/user.service";

@Component({
  selector: "app-dummy-page",
  templateUrl: "./dummy-page.component.html",
  styleUrls: ["./dummy-page.component.scss"],
})
export class DummyPageComponent implements OnInit {
  // Inject the UserService
  constructor(private userService: UserService) {}

  ngOnInit(): void {
    // Ask the service to make an API call on component initialisation
    this.userService.loadAllUsers().subscribe({
      next: (users) => console.log("Users", users),
      error: (error) => console.warn("Error", error),
    });
  }
}
```

If you display the dummy page and check network requests in Chrome's developer tools,
you will see that there is no `Authorization` header sent even when the user is logged in.

Now you can generate the interceptor service:

```bash
$> ng generate service api/ApiTokenInterceptor
```

Put the following content in the generated `src/app/api/api-token.service.ts` file:

```ts
import { Injectable, Injector } from "@angular/core";
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from "@angular/common/http";
import { Observable } from "rxjs";
import { AuthService } from "../security/auth.service";
import { switchMap, first } from "rxjs/operators";

@Injectable({
  providedIn: "root",
})
export class ApiTokenInterceptorService implements HttpInterceptor {
  constructor(private injector: Injector) {}

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    // Retrieve AuthService on method invocation from the Angular injector.
    // (Otherwise there would be a circular dependency:
    //  AuthInterceptorProvider -> AuthService -> HttpClient -> AuthInterceptorProvider).
    const auth = this.injector.get(AuthService);

    // Get the auth token, if any
    return auth.getToken().pipe(
      first(),
      switchMap((token) => {
        // If the token exists and the header does not...
        if (token && !req.headers.has("Authorization")) {
          // Clone the actual request and add it the header
          req = req.clone({
            headers: req.headers.set("Authorization", `Bearer ${token}`),
          });
        }
        // Process this updated request
        return next.handle(req);
      })
    );
  }
}
```

Now you simply need to register the interceptor in your application module.
Since it's an HTTP interceptor, it's not like other providers and must be registered in a special way.
In `src/app/app.module.ts`, add:

```ts
// Other imports...
import { HttpClientModule, HTTP_INTERCEPTORS } from "@angular/common/http";
import { ApiTokenInterceptorService } from "./api/api-token-interceptor.service";

@NgModule({
  // ...
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: ApiTokenInterceptorService,
      multi: true,
    },
  ],
})
export class AppModule {}
```

The `multi: true` option is necessary because you can register multiple interceptors if you want
(read more about [multi providers](https://blog.thoughtram.io/angular2/2015/11/23/multi-providers-in-angular-2.html)).

Now all your API calls will have the `Authorization` header when the user is logged in.

<a href="#top">↑ Back to top</a>

## Multi-environment & sensitive configuration

Sometimes you might have to store values that should not be committed to version control:

- **Environment-specific** values that may change depending on how you deploy your app (e.g. the URL of your API).
- **Sensitive information** like access tokens or passwords.

For example, in our earlier HTTP calls, the URL was **hardcoded**, like in the `AuthService` and the `UserService`.

This is not optimal considering the multi-environment problem: if you have a local instance of the API, it's URL will certainly be different thant when in production.

If you wanted to change environments, you would have to manually change the URL every time.

Let's find a way to centralize this configuration.

<a href="#top">↑ Back to top</a>

### Environment files

There is already a mechanism in place to handle those environment-specific values with Angular.

In `src/environments`, you should find two files: `environment.ts` and `environment.prod.ts`.

The purpose of those file is to hold the configuration values of a specific environment, so that you could easily swap one config with another to deploy your app in different environment ("development", "test", "staging", "production", etc).

The first file, `environment.ts` is the default file and the one that should hold the configuration for your development environment. It should **not be committed** as your development config might be different than the one of your fellows developers.

The other one, `environment.prod.ts`, is the file that will contain production specific values. **It should not be commited** at all.

Alas, both those files have already been commited when the project was set up... It's not a huge problem as both those files don't contain anything sensitive.

You need to tell git to untrack them, though, so **delete both of them** from your filesystem (we'll recreate them later), then **commit those deletions** in git:

```bash
$> rm src/environments/*
$> git add src/environments/*
$> git commit -m "Remove environment files from git"
```

Now, create a placeholder file whose purpose will be to explain to other developers of the project what their own environment file should contains so they could fill in the actual values.
Create the `environment.sample.ts` file in `src/environments`, with this exact content (comment included):

```ts
// Copy this file to environment.ts and fill in appropriate values.
export const environment = {
  production: false,
  apiUrl: "https://example.com/api",
};
```

> The `environment.sample.ts` file is a placeholder and should **NOT** contain the actual configuration.

<a href="#top">↑ Back to top</a>

### Create the actual configuration file

With this placeholder file, you can now (re)create the actual `src/environments/environment.ts` configuration file (by copying the `environment.sample.ts` file), this time containing your actual configuration values, at least for development:

```ts
export const environment = {
  production: false,
  // TODO: Insert here your personnal api URL
  apiUrl: "<REPLACE_ME>",
};
```

While we're at it, let's also (re)create the `environment.prod.ts` file, used for production builds, with this content:

```ts
export const environment = {
  production: true,
  // That's the same api Url in our case, but in real project, it would certainly be different
  // TODO: Insert here your personnal api URL
  apiUrl: "<REPLACE_ME>",
};
```

<a href="#top">↑ Back to top</a>

### Add the environment files to your `.gitignore` file

Of course, you **don't want to commit neither `environment.ts` nor `environment.prod.ts`**, but you do want to commit `environment.sample.ts`
so that anyone who clones your project can see what configuration options are required.
To do so, add these lines at the bottom of your `.gitignore` file:

```
# Environment files
src/environments/*
!src/environments/environment.sample.ts
```

The first line tells git not to track any file in the `src/environments` folder... except for the specific `environment.sample.ts` file (this is the second line).

You now have your uncommitted environment files!

### When are the environment files used

The `environment.ts` file is loaded when you execute the `ng serve` command.

> If you have any `ionic serve` command running, kill it and start it again to apply the changes.

When executing the `ng serve` command with the `--prod` flag, like so...

```bash
$> ng serve --prod
```

> DO NOT use the `--prod` flag when developping! It considerably slows down the compilation/reload time!

...Ionic replaces the content of `environment.ts` file by the content from `environment.prod.ts`, in the build (**it does not replace the content of the actual file, thankfully**).

This way, whatever the environment your app is running on, `environment.ts` is **always the file holding the adequate configuration!**

<a href="#top">↑ Back to top</a>

### Feed the configuration to Angular

Now that you have your configuration file, you want to use its values in your code.

Since it's a TypeScript file like any other that exports a constant, you simply have to import and use it.

> **Remember that you only ever have to import `environment.ts` in your code**, as it's content will change depending on the environment.

Update the `UserService` so that it uses this `environment` object.

```ts
import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { Observable } from "rxjs";
import { User } from "src/app/models/user";
// TODO Import the environment file
import { environment } from "../../../environments/environment";

// TODO remove the apiUrl constant

@Injectable({
  providedIn: "root",
})
export class UserService {
  constructor(private http: HttpClient) {}

  loadAllUsers(): Observable<User[]> {
    // Update the parameter of the get(...) method
    return this.http.get<User[]>(`${environment.apiUrl}/users`);
  }
}
```

Do not forget to also update the authentication service in `src/app/security/auth.service.ts`, which also has a hardcoded URL:

```ts
import { Injectable } from "@angular/core";
import { Observable, ReplaySubject } from "rxjs";
import { AuthResponse } from "../models/auth-response";
import { HttpClient } from "@angular/common/http";
import { map, tap } from "rxjs/operators";
import { User } from "../models/user";
import { AuthRequest } from "../models/auth-request";
// TODO imports the environment file
import { environment } from "../../environments/environment";

// TODO remove the constant
const STORAGE_KEY = "auth";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  // ...

  login(authRequest: AuthRequest): Observable<User> {
    // TODO update the argument of the post(...) method
    return this.http
      .post<AuthResponse>(`${environment.apiUrl}/auth`, authRequest)
      .pipe(/* ... */);
  }

  // ...
}
```

<a href="#top">↑ Back to top</a>

[angular-component]: https://angular.io/guide/architecture#components
[angular-guard]: https://angular.io/guide/router#guards
[cordova]: https://cordova.apache.org/
[ionic]: https://ionicframework.com/
[ionic-tabs]: https://ionicframework.com/docs/components/#tabs
[lazy-loading]: https://angular.io/guide/lazy-loading-ngmodules
[rxjs-delay-when]: http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html#instance-method-delayWhen
[sass]: http://sass-lang.com
[travel-log-api]: https://comem-travel-log-api.herokuapp.com
