# How to create a Verifier

Implement `IVerifier` type (defined in `verification/verifier/iverifier.go`) (we'll call it `verifier`)

Currently, this consists of 3 methods:
* `IsSupportedMediaType`
* `SupportedMediaTypes`
* `ProcessEvidence`

Implement `ISessionManager` type (defined in `verifiersion/sessionmanager/isessionmanager.go`) (we'll call it `session_manager`)

Currently, this consists of 5 methods:
* `Init`
* `SetSession`
* `GetSession`
* `DelSession`
* `Close`

Create a new verification handler: (`Handler` is implemented in `verification/api/handler.go`)

```
    handler = verification::api::NewHandler(session_manager, verifier)
```

`Handler` implements the `IHandler` interface which contains 4 methods:
* `NewChallengeResponse`
* `SubmitEvidence`
* `GetSession`
* `DelSession`

It doesn't look like `Handler` has any public functions outside of the `IHandler` interface. 

My current understanding is that `IHandler` is not an interface that users will implement. Instead, it appears to exist just to identify the public interface to `Handler`. Because otherwise, `golang` makes this difficult.

This next step seems optional (in case you want to implement your own router). Call `verification::api::NewRouter`:
```
    router = verification::api::NewRouter(handler)
```

Then, to run the router:
```
    router.Run(listenAddr)
```

    where `listenAddr` is a `string` containing the IP address and port to listen on.


# How to Implement `IVerifier`

The interface has 3 methods.
* `IsSupportedMediaType` should just be an internal check inside the verifier.
* `SupportedMediaTypes` should also just be a return of an internal array, no?
* `ProcessEvidence` should make a call into a running `vts` (via gRPC) to verify the evidence against provisioned data.

`Handler` definitely calls `IsSupportedMediaType` in its `SubmitEvidence` method (why, oh, why, are we reusing method names in different interfaces?). It also calls `SupportedMediaTypes` as an error condition when the `IsSupportedMediaType` call returns false.

`ProcessEvidence`
