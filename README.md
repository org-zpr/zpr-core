# zpr-core
Core ZPR components

We are currently working towards Milestone 3.  
- See the [current iteration and backlog](https://github.com/orgs/org-zpr/projects/1/views/3).
- See the [roadmap](https://github.com/orgs/org-zpr/projects/3/views/6).


## Build Notes

The thrift generated code comes from its own repository, you need to do a little
configuration in order for the build system to download it:

Developers will have to either run `git config --global url.git@github.com:.insteadOf https://github.com/`
(which ends up in ~/.gitconfig), (or configure a PAT and use git askpass like
the runners now do). Also, anyone developing Golang will have to set `go env -w GOPRIVATE="github.com/org-zpr/*"`
(which ends up in ~/.config/go/env). Again, once we're public this requirement
goes away.



## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in ZPR by you, shall be licensed as Apache 2.0, without any additional
terms or conditions.

