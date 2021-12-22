# Packet Schedule
`net/sched/Kconfig`
```
menuconfig NET_SCHED
    def_bool y
    select NET_SCH_FIFO
    select NET_SCH_FQ_CODEL
    ---help---
      When the kernel has several packets to send out over a network
      device, it has to decide which ones to send first, which ones to
      delay, and which ones to drop. This is the job of the queueing
      disciplines, several different algorithms for how to do this
      "fairly" have been proposed.

      If you say N here, you will get the standard packet scheduler, which
      is a FIFO (first come, first served). If you say Y here, you will be
      able to choose from among several alternative algorithms which can
      then be attached to different network devices. This is useful for
      example if some of your network devices are real time devices that
      need a certain minimum data flow rate, or if you need to limit the
      maximum data flow rate for traffic which matches specified criteria.
      This code is considered to be experimental.
```

```c
int register_netdevice(struct net_device *dev){
            .
            .
            .
    dev_init_scheduler(dev);
            .
            .
            .
}

void dev_init_scheduler(struct net_device *dev) {
    dev->qdisc = &noop_qdisc;
    netdev_for_each_tx_queue(dev, dev_init_scheduler_queue, &noop_qdisc);
    if (dev_ingress_queue(dev))
        dev_init_scheduler_queue(dev, dev_ingress_queue(dev), &noop_qdisc);
    timer_setup(&dev->watchdog_timer, dev_watchdog, 0);
}
```
## API
```c
static int __init pktsched_init(void) {
    int err;

    err = register_pernet_subsys(&psched_net_ops);
    if (err) {
        pr_err("pktsched_init: "
               "cannot initialize per netns operations\n");
        return err;
    }

    register_qdisc(&fq_codel_qdisc_ops);
    register_qdisc(&pfifo_qdisc_ops);
    register_qdisc(&bfifo_qdisc_ops);
    register_qdisc(&pfifo_head_drop_qdisc_ops);
    register_qdisc(&mq_qdisc_ops);
    register_qdisc(&noqueue_qdisc_ops);

    rtnl_register(PF_UNSPEC, RTM_NEWQDISC, tc_modify_qdisc, NULL, 0);
    rtnl_register(PF_UNSPEC, RTM_DELQDISC, tc_get_qdisc, NULL, 0);
    rtnl_register(PF_UNSPEC, RTM_GETQDISC, tc_get_qdisc, tc_dump_qdisc,
              0);
    rtnl_register(PF_UNSPEC, RTM_NEWTCLASS, tc_ctl_tclass, NULL, 0);
    rtnl_register(PF_UNSPEC, RTM_DELTCLASS, tc_ctl_tclass, NULL, 0);
    rtnl_register(PF_UNSPEC, RTM_GETTCLASS, tc_ctl_tclass, tc_dump_tclass,
              0);

    return 0;
}
```
### PROC
### Routing family Netlink