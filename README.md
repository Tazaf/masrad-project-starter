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
  - [Create model types](#create-model-types)
  - [Create an authentication feature module](#create-an-authentication-feature-module)
  - [Create an authentication service](#create-an-authentication-service)
  - [Create the login screen](#create-the-login-screen)
  - [Use the authentication service to protect access to restricted pages](#use-the-authentication-service-to-protect-access-to-restricted-pages)
  - [Storing the authentication credentials](#storing-the-authentication-credentials)
  - [Logout button](#logout-button)
  - [Configuring an HTTP interceptor](#configuring-an-http-interceptor)
- [Multi-environment & sensitive configuration](#multi-environment--sensitive-configuration)
  - [Environment files](#environment-files)
  - [Update the actual configuration file](#update-the-actual-configuration-file)
  - [Feed the environment configuration to Angular](#feed-the-environment-configuration-to-angular)
  - [How are the environment files used by Angular](#how-are-the-environment-files-used-by-angular)
    - [Example setup for production environment](#example-setup-for-production-environment)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Prerequisites

These instructions assume that you are using the Travel Log API and have read its [documentation](https://comem-travel-log-api.onrender.com/).

> You should have or will receive soon the URL of a dedicated API for your projet. Use this URL instead of the demo one as soon as you have it.

You will need to have [Node.js](https://nodejs.org) installed.
The latest LTS (Long Term Support) version is recommended (v18 at the time of writing these instructions).

<a href="#top">↑ Back to top</a>

## Features

The features that the final application should support can be found in [the course introduction subject](https://mediacomem.github.io/comem-masrad-dfa/latest/subjects/intro/#7).

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
Angular CLI: 16.x.x
```

> If you have an error when running the above command, this probably means that you need to install [Angular CLI][ng-cli]. To do so, execute:
>
> ```bash
> $> npm install -g @angular/cli
> ```

Go in the directory where you want the app source code to be located, then generate a blank Angular app with the following command:

> No need to create a dedicated directory for your app ; it will be created for you by the CLI tool

```bash
$> cd /path/to/projects
$> ng new travel-log --routing=true --skip-tests=true
```

> When asked, select the CSS processor of your choice.

> **NOTE: In this starter, we assume that you selected SCSS. If that's not the case, remember to replace any reference to `.scss` file extension by the extension of your selected style.**

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

You can now cleanup the template in `app.component.html` by replacing all the HTML with this simple line:

```html
<router-outlet></router-outlet>
```

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

### Create model types

Let's create a few types to use when communicating with the API.
That way we will benefit from TypeScript's typing when accessing the properties.

Create a `src/app/users/user.model.ts` file which exports a model representing a user of the API:

```ts
export type User = {
  id: string;
  href: string;
  name: string;
  tripsCount: number;
  createdAt: string;
  updatedAt: string;
};
```

> Note that the `createdAt` and `updatedAt` properties are defined as `string` even if they represent dates. This is because the API will always return a JSON representation of the data, and dates are represented as strings in JSON.

> If you want your `User` to have actual `Date` (or any other non-primitive type), you'll need to create appropriate mapping functions or use classes instead of types. This use case won't be covered in this project starter, though.

Create a `src/app/auth/auth-request.model.ts` file which exports a model representing a request to the authentication resource:

```ts
export type AuthRequest = {
  username: string;
  password: string;
};
```

Create a `src/app/auth/auth-response.model.ts` file which exports a model representing a successful response from the authentication resource:

```ts
import { User } from "../users/user.model";

export type AuthResponse = {
  token: string;
  user: User;
};
```

### Create an authentication feature module

We will define several features and utils related to managing security in our app.

Let's group them in a dedicated feature module:

```bash
$> ng generate module Auth
```

> This module does not need `--routing` since it will only provide feature and not directly add new navigation in the final app

### Create an authentication service

Since the new service we'll create will make Http requests, we need to import Angular's `HttpClientModule` in our app. Do so in the `src/app/app.module.ts` file:

```ts
// ...Other imports
// TODO: import Angular's HttpClientModule
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

Now, let's generate a reusable, injectable service to manage authentication in our `auth` directory:

```bash
$> ng generate service auth/Auth
```

You can replace the content of the generated `src/app/auth/auth.service.ts` file with the following code:

> ⚠ **Don't forget to replace `apiUrl` with your custom API base URL !** ⚠

```ts
import { Injectable } from "@angular/core";
import { Observable, ReplaySubject } from "rxjs";
import { HttpClient } from "@angular/common/http";
import { map } from "rxjs/operators";
import { User } from "../users/user.model";
import { AuthRequest } from "./auth-request.model";
import { AuthResponse } from "./auth-response.model";

// TODO: Insert here your personnal api URL
const apiUrl = "<REPLACE_ME>";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  /**
   * A "ReplaySubject" is a Subject (the source of an Observable) that emits a predefined number of previously emitted
   * values to an Observer when it subscribes to it.
   * It will act as a sort of local "cache" for the AuthResponse object value.
   */
  private authenticated$: ReplaySubject<AuthResponse | undefined>;

  constructor(private http: HttpClient) {
    // Create the ReplaySubject and configure it so that it emits the latest emitted value on each subscription
    this.authenticated$ = new ReplaySubject(1);
    // Emit an undefined value as the initial value, since our user is not logged in
    this.authenticated$.next(undefined);
  }

  /**
   * Checks if the user is authenticated by casting the latest AuthResponse value as a boolean
   */
  isAuthenticated$(): Observable<boolean> {
    return this.authenticated$.pipe(map((auth) => Boolean(auth)));
  }

  /**
   * Retrieves the User object from the latest AuthResponse value
   */
  getUser$(): Observable<User | undefined> {
    return this.authenticated$.pipe(map((auth) => auth?.user));
  }

  /**
   * Retrieves the token string from the latest AuthResponse value
   */
  getToken$(): Observable<string | undefined> {
    return this.authenticated$.pipe(map((auth) => auth?.token));
  }

  /**
   * Logs in a user with the provided AuthRequest object and emits the received AuthResponse if successful.
   */
  login$(authRequest: AuthRequest): Observable<User> {
    return this.http.post<AuthResponse>(`${apiUrl}/auth`, authRequest).pipe(
      map((response) => {
        this.authenticated$.next(response);
        return response.user;
      })
    );
  }

  /**
   * Logs out a user and emit an empty AuthResponse
   */
  logout() {
    this.authenticated$.next(undefined);
  }
}
```

### Create the login screen

Generate a login page component for the `AuthModule`:

```bash
$> ng generate component auth/LoginPage
```

Since this login screen will be composed of a form, you'll need to import the `FormsModule` in your `AuthModule`.

While you're at it, add the `LoginPageComponent` to the `exports` array of the `AuthModule` configuration in `auth.module.ts`, to make it accessible when importing the `AuthModule` into another module :

```ts
// Imports
import { FormsModule } from "@angular/forms";

@NgModule({
  // ...
  imports: [CommonModule, FormsModule],
  // ...
  exports: [LoginPageComponent],
})
export class AuthModule {}
```

Update the generated `src/app/auth/login-page/login-page.component.ts` as follows:

```ts
import { Component } from "@angular/core";
import { NgForm } from "@angular/forms";
import { Router } from "@angular/router";
import { AuthService } from "../auth.service";
import { AuthRequest } from "../auth-request.model";

@Component({
  selector: "app-login-page",
  templateUrl: "./login-page.component.html",
  styleUrls: ["./login-page.component.css"],
})
export class LoginPageComponent {
  /**
   * This authentication request object will be updated when the user
   * edits the login form. It will then be sent to the API.
   *
   * Partial is a generic typescript that creates a type from the type param,
   * with all the properties optionally undefined.
   */
  authRequestInput: Partial<AuthRequest>;

  /**
   * If defined, it means that the authentication API has return a failed response
   * (probably because the name or password is incorrect).
   */
  loginError?: string;

  constructor(private auth: AuthService, private router: Router) {
    this.authRequestInput = {};
  }

  /**
   * Called when the login form is submitted.
   */
  onSubmit(form: NgForm) {
    // Only do something if the form is valid
    if (form.valid) {
      // Hide any previous login error.
      this.loginError = undefined;

      // Perform the authentication request to the API.
      // Since the login$() method requires an AuthRequest param, but
      // our authRequestInput has optional properties, we need to convert it
      // to an new object that matches the AuthRequest type.
      this.auth
        .login$({
          password: this.authRequestInput.password ?? "",
          username: this.authRequestInput.username ?? "",
        })
        .subscribe({
          next: () => this.router.navigateByUrl("/"),
          error: (err) => (this.loginError = err.message),
        });
    }
  }
}
```

Replace the content of the generated `src/app/auth/login-page/login-page.component.html` file with:

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
      [(ngModel)]="authRequestInput.username"
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
      [(ngModel)]="authRequestInput.password"
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
import { LoginPageComponent } from "./auth/login-page/login-page.component";

const routes: Routes = [
  {
    path: "login",
    component: LoginPageComponent,
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
```

You'll also need to add the `AuthModule` in the `exports` array of `AppModule` so that the `LoginComponent` can properly be accessed.

```ts
// Other imports
import { AuthModule } from "./auth/auth.module";

@NgModule({
  declarations: [
    /* ... */
  ],
  imports: [, /* other imports */ AuthModule],
  providers: [],
  bootstrap: [AppComponent],
})
export class AppModule {}
```

<a href="#top">↑ Back to top</a>

### Use the authentication service to protect access to restricted pages

Now that we have a service to manage authentication and a working page for users to log in, we need to make sure that unauthenticated user can not access restricted pages and are instead redirected to the login page.

We will use an [Angular Guard][angular-guard] to do this.

```bash
$> ng generate guard auth/guards/Auth
```

> When asked what interface you'd like to implement, select only the `CanActivate` interface.

Open the `src/app/auth/guards/auth.guard.ts` file and **replace all its content** with:

```ts
import { inject } from "@angular/core";
import { CanActivateFn, Router } from "@angular/router";
import { AuthService } from "../auth.service";
import { map } from "rxjs";

export const authGuard: CanActivateFn = () => {
  // The inject() function can be used to get an @Injectable singleton "manually".
  const authService = inject(AuthService);
  const router = inject(Router);

  return (
    authService
      // Use this to check if the user is authenticated
      .isAuthenticated$()
      // If they're authenticated, return true, otherwise, returns an UrlTree to redirect to the login page
      .pipe(map((auth) => (auth ? true : router.parseUrl("/login"))))
  );
};
```

To test this guard, let's create a dummy page that we'll use as the default page of our app:

```bash
$> ng generate component DummyPage
```

> You'll be able to delete this page once you have created your real default page

Then open the `src/app/app-routing.module.ts` file and add a new route for this page:

```ts
import { DummyPageComponent } from "./dummy-page/dummy-page.component";
import { authGuard } from "./auth/guards/auth.guard";
// Other imports

const routes: Routes = [
  // Add this default route to redirect to dummy
  { path: "", redirectTo: "dummy", pathMatch: "full" },
  {
    path: "login",
    component: LoginPageComponent,
  },
  {
    path: "dummy",
    component: DummyPageComponent,
    // Prevent access to this page to unauthenticated users
    canActivate: [authGuard],
  },
];
```

The login screen is ready!
If you reload your app, you should see that you are automatically redirected to the login page.

You should be able to log in using the credentials your should have received.

<a href="#top">↑ Back to top</a>

### Storing the authentication credentials

Now you can log in, but there's a little problem.

Every time the app is reloaded, you lose all data so you have to log back in.
This is particularly annoying for local development since the browser is automatically refreshed every time you change the code.

You need to use more persistent storage for the security credentials, i.e. the authentication token.

We will use the `LocalStorage` feature of HTML5 to do so.

Update the `src/app/auth/auth.service.ts` file to add the necessary `localStorage` calls:

```ts
// Imports & API URL

// Add a constant for the storage key in the LocalStorage
const AUTH_STORAGE_KEY = "travel-log-auth";

@Injectable({
  /* ... */
})
export class AuthService {
  constructor(private http: HttpClient) {
    this.authenticated$ = new ReplaySubject(1);
    // Get the credentials from the localStorage when the AuthService is created
    // It will either contains an AuthResponse object of null if it does not exist
    const savedAuth = localStorage.getItem(AUTH_STORAGE_KEY);
    // If there is a savedAuth, parse it to an object and emit it as the initial authentication value,
    // otherwise, emit undefined.
    this.authenticated$.next(savedAuth ? JSON.parse(savedAuth) : undefined);
  }

  // ...

  login$(authRequest: AuthRequest): Observable<User> {
    return this.http.post<AuthResponse>(`${apiUrl}/auth`, authRequest).pipe(
      // The tap operator allows you to do something with an observable's emitted value
      // and emit it again unaltered.
      // In our case, we just store this AuthResponse in the localStorage
      tap((response) => this.#saveAuth(response)),
      map((response) => {
        // ...
      })
    );
  }

  logout() {
    // Remove the AuthResponse from the localStorage when user logs out
    localStorage.removeItem(AUTH_STORAGE_KEY);
    // ...
  }

  /**
   * Saves the AuthResponse in the localStorage
   */
  #saveAuth(authResponse: AuthResponse): void {
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authResponse));
  }
}
```

Your app should now remember user credentials even when you reload it!

<a href="#top">↑ Back to top</a>

### Logout button

You should also add a UI component to allow the user to log out.

Let's create a dedicated component for that in our `AuthModule`:

```bash
$> ng generate component auth/LogoutButton --export
```

> The `--export` param will update the `AuthModule`'s `exports` array to incldue the newly created `LogoutButton`, so that other modules can access it.

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

But it's a bit annoying to have to manually specify this header for every request (seriously... don't do that).
After all, we know that we need it for most calls.

[Interceptors](https://medium.com/@ryanchenkie_40935/angular-authentication-using-the-http-client-and-http-interceptors-2f9d1540eb8)
are Angular services that can be registered on the HTTP client to automatically react to requests (or responses).
This solves our problem: we want to register an interceptor that will automatically add the `Authorization` header to all requests if the user is logged in.

Let's create a service that will be responsible of calling the Travel Log API to list all users.

> You should create a service for each of the resources that the API allows you to manage, and refrains from doing any HTTP calls from your components.

```bash
$> ng generate service users/UserApi
```

Replace the content of the generated `src/app/users/user-api.service.ts` file with:

```ts
import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { Observable } from "rxjs";
import { User } from "./user.model";

// TODO: Insert here your personnal api URL
const apiUrl = "<REPLACE_ME>";

@Injectable({
  providedIn: "root",
})
export class UserApiService {
  constructor(private http: HttpClient) {}

  loadAllUsers$(): Observable<User[]> {
    return this.http.get<User[]>(`${apiUrl}/users`);
  }
}
```

Now, update the `DummyPageComponent` to add the following code:

```ts
import { Component, OnInit } from "@angular/core";
import { UserApiService } from "../users/user-api.service";

@Component({
  selector: "app-dummy-page",
  templateUrl: "./dummy-page.component.html",
  styleUrls: ["./dummy-page.component.scss"],
})
export class DummyPageComponent implements OnInit {
  constructor(private readonly userApi: UserApiService) {}

  ngOnInit(): void {
    // Ask the service to make an API call on component initialisation
    this.userApi.loadAllUsers$().subscribe({
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
$> ng generate service auth/ApiTokenInterceptor
```

Put the following content in the generated `src/app/auth/api-token.service.ts` file:

```ts
import { Injectable, Injector, inject } from "@angular/core";
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from "@angular/common/http";
import { Observable } from "rxjs";
import { switchMap, first } from "rxjs/operators";
import { AuthService } from "./auth.service";

@Injectable({
  providedIn: "root",
})
export class ApiTokenInterceptorService implements HttpInterceptor {
  #auth?: AuthService;

  // Inject the AuthService only when we need to acccess it.
  // Otherwise there would be a circular dependency:
  //  AuthInterceptorProvider -> AuthService -> HttpClient -> AuthInterceptorProvider.
  get auth(): AuthService {
    if (this.#auth === undefined) {
      this.#auth = inject(AuthService);
    }
    return this.#auth;
  }

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    // Get the auth token, if any
    return this.auth.getToken$().pipe(
      // getToken$ is an Observable that never completes.
      // But an Angular Interceptor must provide an Observable that completes,
      // otherwise the request handling hangs indefinitely.
      // The first() operator creates an Observable that emit the first value
      // emitted by its source observable (here getToken$()), then completes.
      first(),
      switchMap((token) => {
        // If the token exists and the header does not...
        if (token !== undefined && !req.headers.has("Authorization")) {
          // Clone the actual request and add the required header
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

Now you simply need to register this interceptor in your main application module.
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

> You can check that it's the case in the Network tab of your browser's Developer Tools

<a href="#top">↑ Back to top</a>

## Multi-environment & sensitive configuration

Sometimes you might have to store values that should not be committed to version control:

- **Environment-specific** values that may change depending on how you deploy your app (e.g. the URL of your API).
- **Sensitive information** like access tokens or passwords.

For example, in our earlier HTTP calls, the URL was **hardcoded**, like in the `AuthService` and the `UserService`.

This is not optimal considering the multi-environment problem: if you have a local instance of the API, it's URL will certainly be different than when in production.

If you wanted to change environments, you would have to manually change the URL every time.

Let's find a way to centralize this configuration.

<a href="#top">↑ Back to top</a>

### Environment files

Angular offers a minimalist mechanism for environment files. You must opt-in to use those environments files by using the command `ng generate environments`.

This will generate a new directory at `src/environments`, and update your application `angular.json` configuration.

In `src/environments`, you should find two files: `environment.development.ts` and `environment.ts`.

The purpose of those file is to hold the configuration values of a specific environment, so that you could easily swap one config with another to deploy your app in different environment ("development", "test", "staging", "production", etc).

The first file, `environment.development.ts` is the file that should hold the configuration for your own development environment.

The other one, `environment.ts`, is the file that is actually imported in your code. It will act as a placeholder file that will define and explain each of the needed and/or required environment variables for your application to run.

Actual environment files (the one with the real values) **should not be commited** in your repository. They can contain sensitive information (API key, email password, encryption key, etc), and they can differ greatly from one environment to the other.

But the placeholder `environment.ts` file **must be commited**. Otherwise, your fellow developers won't know what is expected.

To tell git not to track environment files other than `environment.ts`, add those lines at the end of your `.gitignore` file:

```
src/environments/*
!src/environments/environment.ts
```

<a href="#top">↑ Back to top</a>

### Update the actual configuration file

Currently, we only need a single environment variable in our application, which is the API URL.

To enforce each of the environment file to have the proper value for the environment variable, we can define a `type` that will define them. Let's do so in a dedicated file `environment.type.ts`:

```ts
export type Environment = {
  /**
   * The Travel Log API URL
   */
  apiUrl: string;
};
```

With this type, we can update the other environment files to type the `environment` constant that is exported:

```ts
// Import the type
import { Environment } from "./environment.type";

// ---------------------[ Add the type ]
export const environment: Environment = {
  /* ... */
};
```

> Now, each time we need to add a new environment variable to our app, we update the type, and the app won't compile until we set this new variable value in all our environment files. Yeay, Typescript!

### Feed the environment configuration to Angular

Now that you have your environment file, you want to use its values in your code.

Since it's a TypeScript file like any other that exports a constant, you simply have to import and use it.

> **Your code only need to import `environment.ts`. We will see later on how Angular effectively uses the appropriate environment file depending on the environment.**

Update the `UserApiService` so that it uses this `environment` object.

```ts
import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { Observable } from "rxjs";
import { User } from "./user.model";
// Import environment.ts
import { environment } from "src/environments/environment";

@Injectable({
  providedIn: "root",
})
export class UserApiService {
  constructor(private http: HttpClient) {}

  loadAllUsers$(): Observable<User[]> {
    // ---------------------------[ Update the param ]----------
    return this.http.get<User[]>(`${environment.apiUrl}/users`);
  }
}
```

Do not forget to also update the authentication service in `src/app/auth/auth.service.ts`, which also has a hardcoded URL:

```ts
// Other imports
import { environment } from "src/environments/environment";

const AUTH_STORAGE_KEY = "travel-log-auth";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  /* ... */

  /**
   * Logs in a user with the provided AuthRequest object and emits the received AuthResponse if successful.
   */
  login$(authRequest: AuthRequest): Observable<User> {
    return (
      this.http
        // ------------------[ Update the param ]---------------------
        .post<AuthResponse>(`${environment.apiUrl}/auth`, authRequest)
        .pipe
        /* ... */
        ()
    );
  }

  /* ... */
}
```

<a href="#top">↑ Back to top</a>

### How are the environment files used by Angular

The `environment.ts` file is directly imported by your code. So how is it that it's the content of `environment.development.ts` which is used when `ng serve`-ing the app?

The answer lies in `angular.json`, specifically in the `projects.travel-log.architect.build.configurations` array. Here we can define how angular behave when building for different environment. You already should have two configurations ; one for `production`, the other for `development`.

In the `development` configuration, you can find the `fileReplacements` array with this replacement object:

```json
"fileReplacements": [
  {
    "replace": "src/environments/environment.ts",
    "with": "src/environments/environment.development.ts"
  }
]
```

This tells Angular that, when building for development, it must uses the content of the `environment.development.ts` file as the content for `environment.ts`.

#### Example setup for production environment

So... if you'd want to have a production configuration, you would need to create a new file `environment.production.ts` in your `src/environments` directory, which would export an `Environment` constant with the proper values for your production build.

**For example**:

```ts
import { Environment } from "./environment.type";

export const environment: Environment = {
  apiUrl: "https://api.travel-log.com",
};
```

You'd also need to add a `fileReplacements` array in the `production` configuration in `angular.json`, which would replace the content of `environment.ts` with `environment.production.ts`:

```json
"fileReplacements": [
  {
    "replace": "src/environments/environment.ts",
    "with": "src/environments/environment.production.ts"
  }
]
```

Now, if you execute the command...

```
ng build --configuration production
```

...Angular will use the values of `environment.production.ts` when generating your app's `.js` files.

<a href="#top">↑ Back to top</a>

[angular-component]: https://angular.io/guide/architecture#components
[angular-guard]: https://angular.io/guide/router#preventing-unauthorized-access
[cordova]: https://cordova.apache.org/
[ionic]: https://ionicframework.com/
[ionic-tabs]: https://ionicframework.com/docs/components/#tabs
[lazy-loading]: https://angular.io/guide/lazy-loading-ngmodules
[rxjs-delay-when]: http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html#instance-method-delayWhen
[sass]: http://sass-lang.com
[travel-log-api]: https://comem-travel-log-api.onrender.com/
